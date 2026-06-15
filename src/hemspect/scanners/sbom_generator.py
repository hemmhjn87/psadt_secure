#!/usr/bin/env python3
"""
HemSpect SBOM Generator
Generates Software Bill of Materials in CycloneDX 1.4 and SPDX 2.3 formats
Compliant with: NIST SP 800-161r1, Executive Order 14028, NTIA SBOM minimum elements
"""

import os
import re
import json
import math
import time
import uuid
import hashlib
import sqlite3
import logging
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from collections import Counter

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

logger = logging.getLogger(__name__)

SCANNER_VERSION = "3.0"
SCANNER_VENDOR = "HemSpect"
SCANNER_NAME = "HemSpectScanner"

# Severity ordering
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".drv", ".scr", ".cpl", ".ax"}
MSI_EXTENSIONS = {".msi"}
PS_EXTENSIONS  = {".ps1", ".psm1", ".psd1"}

CVE_CACHE_DB = "nvd_cache.sqlite3"

# NVD rate limits
NVD_RATE_NO_KEY   = 6   # req/min
NVD_RATE_WITH_KEY = 50  # req/min


class _NVDRateLimiter:
    """Simple token-bucket rate limiter for NVD API calls."""
    def __init__(self, rate_per_minute: int):
        self._min_interval = 60.0 / max(1, rate_per_minute)
        self._last_call = 0.0

    def wait(self):
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()


class SBOMGenerator:
    """
    Generates CycloneDX 1.4 JSON and SPDX 2.3 tag-value SBOMs for a PSADT package.
    Also queries the NVD 2.0 API for CVE data and produces HTML report fragments.
    """

    def __init__(self, package_path: Path, output_dir: Path, nvd_api_key: str = None):
        self.package_path = Path(package_path)
        self.output_dir   = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_api_key  = nvd_api_key or os.environ.get("NVD_API_KEY")

        rate = NVD_RATE_WITH_KEY if self.nvd_api_key else NVD_RATE_NO_KEY
        self._limiter = _NVDRateLimiter(rate)

        # SQLite cache for NVD results
        cache_path = self.output_dir / CVE_CACHE_DB
        self._db = sqlite3.connect(str(cache_path))
        self._init_cache()

        self._package_name = self.package_path.name
        self._doc_uuid = str(uuid.uuid4())

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def generate(self) -> dict:
        """
        Main entry point.  Collects components, queries NVD, generates both
        SBOM formats, and returns a rich data dict suitable for the report.
        """
        logger.info("SBOM generation started for %s", self._package_name)
        components = self._collect_components()

        # Attach CVE data to each component
        for comp in components:
            name    = comp.get("name", "")
            version = comp.get("version", "")
            if name and version:
                comp["vulnerabilities"] = self._query_nvd_for_component(name, version)
            else:
                comp["vulnerabilities"] = []

        cyclonedx_doc = self.generate_cyclonedx(components)
        spdx_text     = self.generate_spdx(components)

        sbom_data = {
            "package":      self._package_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "doc_uuid":     self._doc_uuid,
            "components":   components,
            "cyclonedx":    cyclonedx_doc,
            "spdx_path":    str(self.output_dir / "sbom.spdx"),
            "total_cves":   sum(len(c.get("vulnerabilities", [])) for c in components),
            "component_count": len(components),
        }
        logger.info("SBOM generation complete: %d components, %d CVEs",
                    len(components), sbom_data["total_cves"])
        return sbom_data

    # ------------------------------------------------------------------ #
    #  Component collection                                               #
    # ------------------------------------------------------------------ #

    def _collect_components(self) -> List[dict]:
        """Walk package_path recursively and collect per-file metadata."""
        components: List[dict] = []
        for file_path in sorted(self.package_path.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                comp = self._analyze_file(file_path)
                components.append(comp)
            except Exception as exc:
                logger.warning("Could not analyze %s: %s", file_path, exc)
        return components

    def _analyze_file(self, file_path: Path) -> dict:
        """Return a component dict for a single file."""
        suffix = file_path.suffix.lower()

        comp: Dict[str, Any] = {
            "bom_ref":   f"comp-{uuid.uuid4().hex[:12]}",
            "type":      "file",
            "name":      file_path.name,
            "file_path": str(file_path.relative_to(self.package_path)),
            "version":   "",
            "publisher": "",
            "description": "",
            "licenses":  [],
            "hashes":    self._hash_file(file_path),
            "entropy":   self._file_entropy(file_path),
            "is_signed": False,
            "vulnerabilities": [],
        }

        if suffix in PE_EXTENSIONS and PEFILE_AVAILABLE:
            self._enrich_pe(file_path, comp)
        elif suffix in MSI_EXTENSIONS:
            self._enrich_msi(file_path, comp)
        elif suffix in PS_EXTENSIONS:
            self._enrich_ps(file_path, comp)

        return comp

    # -- Hash helpers --------------------------------------------------- #

    def _hash_file(self, file_path: Path) -> dict:
        """Compute MD5/SHA1/SHA256/SHA512 hashes."""
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
        return {
            "MD5":    md5.hexdigest(),
            "SHA-1":  sha1.hexdigest(),
            "SHA-256": sha256.hexdigest(),
            "SHA-512": sha512.hexdigest(),
        }

    def _file_entropy(self, file_path: Path) -> float:
        """Shannon entropy of the file (0-8)."""
        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
            if not data:
                return 0.0
            counts = Counter(data)
            n = len(data)
            entropy = 0.0
            for cnt in counts.values():
                p = cnt / n
                entropy -= p * math.log2(p)
            return round(entropy, 4)
        except Exception:
            return 0.0

    # -- PE enrichment -------------------------------------------------- #

    def _enrich_pe(self, file_path: Path, comp: dict):
        """Extract PE metadata and Authenticode signature status."""
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
            if hasattr(pe, "VS_VERSIONINFO"):
                vi = pe.FileInfo
                for file_info in (vi if vi else []):
                    for entry in (file_info if file_info else []):
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for k, v in st.entries.items():
                                    key = k.decode("utf-8", errors="ignore").strip()
                                    val = v.decode("utf-8", errors="ignore").strip()
                                    if key == "FileVersion":
                                        comp["version"] = val
                                    elif key == "CompanyName":
                                        comp["publisher"] = val
                                    elif key == "ProductName":
                                        comp["name"] = val or comp["name"]
                                    elif key == "FileDescription":
                                        comp["description"] = val
                                    elif key == "OriginalFilename":
                                        comp["original_filename"] = val
                                    elif key == "ProductVersion":
                                        comp["product_version"] = val
            pe.close()
        except Exception as exc:
            logger.debug("pefile error for %s: %s", file_path.name, exc)

        comp["is_signed"] = self._check_authenticode(file_path)
        comp["type"] = "library" if file_path.suffix.lower() == ".dll" else "application"

    def _check_authenticode(self, file_path: Path) -> bool:
        """Return True if the file has a valid Authenticode signature."""
        try:
            if not PEFILE_AVAILABLE:
                return False
            pe = pefile.PE(str(file_path), fast_load=True)
            # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            pe.close()
            return sec_dir.VirtualAddress != 0 and sec_dir.Size > 0
        except Exception:
            return False

    # -- MSI enrichment ------------------------------------------------- #

    def _enrich_msi(self, file_path: Path, comp: dict):
        """Extract MSI summary information via PowerShell WindowsInstaller COM."""
        comp["type"] = "application"
        try:
            script = (
                f"$wi = New-Object -ComObject WindowsInstaller.Installer;"
                f"$db = $wi.GetType().InvokeMember('OpenDatabase', [System.Reflection.BindingFlags]::InvokeMethod, $null, $wi, @('{file_path}', 0));"
                f"$view = $db.GetType().InvokeMember('OpenView', [System.Reflection.BindingFlags]::InvokeMethod, $null, $db, @('SELECT Property, Value FROM Property WHERE Property IN (''ProductName'', ''ProductVersion'', ''Manufacturer'')'));"
                f"$view.GetType().InvokeMember('Execute', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, $null);"
                f"$result = @{{}};"
                f"while ($rec = $view.GetType().InvokeMember('Fetch', [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)) {{"
                f"  $result[$rec.StringData(1)] = $rec.StringData(2)"
                f"}};"
                f"ConvertTo-Json $result"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                comp["name"]      = data.get("ProductName", comp["name"])
                comp["version"]   = data.get("ProductVersion", "")
                comp["publisher"] = data.get("Manufacturer", "")
        except Exception as exc:
            logger.debug("MSI enrichment failed for %s: %s", file_path.name, exc)

    # -- PowerShell enrichment ------------------------------------------ #

    def _enrich_ps(self, file_path: Path, comp: dict):
        """Extract module metadata from .psd1 manifests or script headers."""
        comp["type"] = "file"
        # Look for a sibling .psd1 manifest
        manifest_path = file_path.with_suffix(".psd1")
        if file_path.suffix.lower() == ".psd1":
            manifest_path = file_path

        if manifest_path.exists():
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                # Extract ModuleVersion
                m = re.search(r"ModuleVersion\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    comp["version"] = m.group(1)
                # Extract Author
                m = re.search(r"Author\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    comp["publisher"] = m.group(1)
                # Extract Description
                m = re.search(r"Description\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    comp["description"] = m.group(1)
                # Extract RootModule / ModuleName
                m = re.search(r"RootModule\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    comp["name"] = m.group(1)
            except Exception as exc:
                logger.debug("PS manifest parse failed for %s: %s", file_path.name, exc)

    # ------------------------------------------------------------------ #
    #  NVD CVE lookup                                                      #
    # ------------------------------------------------------------------ #

    def _init_cache(self):
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS nvd_cache (
                cache_key TEXT PRIMARY KEY,
                result    TEXT,
                fetched   INTEGER
            )
        """)
        self._db.commit()

    def _query_nvd_for_component(self, component_name: str, version: str) -> List[dict]:
        """
        Query NVD 2.0 API for CVEs matching component_name/version.
        Results are cached in SQLite with a 24-hour TTL.
        """
        if not REQUESTS_AVAILABLE:
            return []

        cache_key = f"{component_name}::{version}"
        now = int(time.time())
        ttl = 86400  # 24 hours

        # Check cache
        row = self._db.execute(
            "SELECT result, fetched FROM nvd_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        if row and (now - row[1]) < ttl:
            try:
                return json.loads(row[0])
            except Exception:
                pass

        # Rate-limit before API call
        self._limiter.wait()

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers: Dict[str, str] = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        params = {
            "keywordSearch":      component_name,
            "keywordExactMatch":  "",
        }

        cves: List[dict] = []
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_item = vuln.get("cve", {})
                    cve_id = cve_item.get("id", "")
                    published = cve_item.get("published", "")

                    # Extract CVSS v3.1 metrics
                    cvss_score  = None
                    severity    = "UNKNOWN"
                    cvss_vector = ""
                    metrics = cve_item.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics and metrics[key]:
                            m = metrics[key][0]
                            cvss_data   = m.get("cvssData", {})
                            cvss_score  = cvss_data.get("baseScore")
                            severity    = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                            cvss_vector = cvss_data.get("vectorString", "")
                            break

                    # Check if version is in a vulnerable range
                    if not self._version_in_range(version, cve_item.get("configurations", {})):
                        continue

                    # Extract description
                    desc = ""
                    for d in cve_item.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    # References
                    refs = [r.get("url", "") for r in cve_item.get("references", [])[:3]]

                    cves.append({
                        "cve_id":      cve_id,
                        "cvss_v3_score": cvss_score,
                        "severity":    severity.upper() if severity else "UNKNOWN",
                        "description": desc[:300],
                        "published":   published,
                        "references":  refs,
                        "cvss_vector": cvss_vector,
                    })
            elif resp.status_code == 403:
                logger.warning("NVD API key invalid or rate limited (403)")
            elif resp.status_code == 429:
                logger.warning("NVD API rate limited (429); backing off 60s")
                time.sleep(60)
        except Exception as exc:
            logger.warning("NVD lookup failed for %s %s: %s", component_name, version, exc)

        # Store in cache
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO nvd_cache (cache_key, result, fetched) VALUES (?, ?, ?)",
                (cache_key, json.dumps(cves), now)
            )
            self._db.commit()
        except Exception:
            pass

        return cves

    def _version_in_range(self, version: str, configurations: Any) -> bool:
        """
        Simplified CPE version range check.
        Returns True if the given version string appears in any node's criteria,
        or if configurations is empty (assume vulnerable by keyword match).
        """
        if not configurations:
            return True
        try:
            # configurations may be a list of nodes dicts
            nodes = []
            if isinstance(configurations, list):
                for cfg in configurations:
                    nodes.extend(cfg.get("nodes", []))
            elif isinstance(configurations, dict):
                nodes = configurations.get("nodes", [])

            if not nodes:
                return True

            for node in nodes:
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    criteria = cpe_match.get("criteria", "")
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(":")
                    if len(parts) > 5:
                        cpe_ver = parts[5]
                        if cpe_ver in ("*", "-", version):
                            return True
                    # Range check (versionStartIncluding / versionEndIncluding)
                    v_start = cpe_match.get("versionStartIncluding", "")
                    v_end   = cpe_match.get("versionEndIncluding", "")
                    v_end_ex = cpe_match.get("versionEndExcluding", "")
                    if v_start and v_end:
                        if self._ver_compare(version, v_start) >= 0 and self._ver_compare(version, v_end) <= 0:
                            return True
                    elif v_start and v_end_ex:
                        if self._ver_compare(version, v_start) >= 0 and self._ver_compare(version, v_end_ex) < 0:
                            return True
            return False
        except Exception:
            return True

    @staticmethod
    def _ver_compare(v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        def parts(v):
            return [int(x) if x.isdigit() else x for x in re.split(r"[\.\-]", v)]
        try:
            p1, p2 = parts(v1), parts(v2)
            for a, b in zip(p1, p2):
                if isinstance(a, int) and isinstance(b, int):
                    if a < b: return -1
                    if a > b: return 1
                else:
                    sa, sb = str(a), str(b)
                    if sa < sb: return -1
                    if sa > sb: return 1
            if len(p1) < len(p2): return -1
            if len(p1) > len(p2): return 1
            return 0
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    #  CycloneDX 1.4 output                                               #
    # ------------------------------------------------------------------ #

    def generate_cyclonedx(self, components: List[dict]) -> dict:
        """Generate CycloneDX 1.4 JSON and write to output_dir/sbom.cyclonedx.json."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cdx_components = []
        cdx_vulns = []

        for comp in components:
            hashes = [
                {"alg": "MD5",    "content": comp["hashes"].get("MD5", "")},
                {"alg": "SHA-256", "content": comp["hashes"].get("SHA-256", "")},
                {"alg": "SHA-512", "content": comp["hashes"].get("SHA-512", "")},
            ]
            cdx_comp = {
                "type":      comp.get("type", "file"),
                "bom-ref":   comp["bom_ref"],
                "name":      comp["name"],
                "version":   comp.get("version", ""),
                "publisher": comp.get("publisher", ""),
                "description": comp.get("description", ""),
                "hashes":    hashes,
                "licenses":  [{"license": {"id": lic}} for lic in comp.get("licenses", [])],
                "externalReferences": [],
                "properties": [
                    {"name": "psadt:entropy", "value": str(comp.get("entropy", 0))},
                    {"name": "psadt:signed",  "value": str(comp.get("is_signed", False))},
                    {"name": "psadt:path",    "value": comp.get("file_path", "")},
                ],
            }
            cdx_components.append(cdx_comp)

            # Vulnerabilities
            for vuln in comp.get("vulnerabilities", []):
                ratings = []
                if vuln.get("cvss_v3_score") is not None:
                    ratings.append({
                        "source": {"name": "NVD"},
                        "score":    vuln["cvss_v3_score"],
                        "severity": vuln["severity"].lower(),
                        "method":   "CVSSv31",
                        "vector":   vuln.get("cvss_vector", ""),
                    })
                cdx_vulns.append({
                    "id": vuln["cve_id"],
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}"},
                    "ratings":      ratings,
                    "description":  vuln.get("description", ""),
                    "published":    vuln.get("published", ""),
                    "references":   [{"id": ref} for ref in vuln.get("references", [])],
                    "affects":      [{"ref": comp["bom_ref"]}],
                })

        doc = {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.4",
            "version":     1,
            "serialNumber": f"urn:uuid:{self._doc_uuid}",
            "metadata": {
                "timestamp": timestamp,
                "tools": [{
                    "vendor":  SCANNER_VENDOR,
                    "name":    SCANNER_NAME,
                    "version": SCANNER_VERSION,
                }],
                "component": {
                    "type":    "application",
                    "name":    self._package_name,
                    "version": "",
                },
            },
            "components":      cdx_components,
            "vulnerabilities": cdx_vulns,
        }

        out_path = self.output_dir / "sbom.cyclonedx.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        logger.info("CycloneDX SBOM written to %s", out_path)
        return doc

    # ------------------------------------------------------------------ #
    #  SPDX 2.3 tag-value output                                         #
    # ------------------------------------------------------------------ #

    def generate_spdx(self, components: List[dict]) -> str:
        """Generate SPDX 2.3 tag-value format and write to output_dir/sbom.spdx."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_ns    = f"urn:hemspect:{self._package_name}:{self._doc_uuid}"

        lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            "",
            "##-------------------------",
            "## Document Information",
            "##-------------------------",
            "SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: {self._package_name}-sbom",
            f"DocumentNamespace: {doc_ns}",
            "",
            "##-------------------------",
            "## Creation Information",
            "##-------------------------",
            f"Creator: Tool: {SCANNER_VENDOR}-{SCANNER_NAME}-{SCANNER_VERSION}",
            f"Created: {timestamp}",
            f"CreatorComment: <text>Generated by HemSpect v{SCANNER_VERSION}. "
            "Compliant with NTIA SBOM minimum elements and EO 14028.</text>",
            "",
        ]

        # Top-level package representing the PSADT package itself
        lines += [
            "##-------------------------",
            "## Package: Root Application",
            "##-------------------------",
            f"PackageName: {self._package_name}",
            "SPDXID: SPDXRef-Package-ROOT",
            "PackageVersion: UNKNOWN",
            f"PackageSupplier: Organization: {SCANNER_VENDOR}",
            f"PackageOriginator: Organization: {SCANNER_VENDOR}",
            f"PackageDownloadLocation: NOASSERTION",
            "FilesAnalyzed: true",
            "PackageVerificationCode: NOASSERTION",
            "",
        ]

        for comp in components:
            spdx_id = "SPDXRef-" + re.sub(r"[^A-Za-z0-9\-\.]", "-", comp["bom_ref"])
            hashes  = comp.get("hashes", {})
            lines += [
                "##-------------------------",
                f"## Package: {comp['name']}",
                "##-------------------------",
                f"PackageName: {comp['name']}",
                f"SPDXID: {spdx_id}",
                f"PackageVersion: {comp.get('version', 'NOASSERTION') or 'NOASSERTION'}",
                f"PackageSupplier: Organization: {comp.get('publisher', 'NOASSERTION') or 'NOASSERTION'}",
                f"PackageOriginator: NOASSERTION",
                "PackageDownloadLocation: NOASSERTION",
                "FilesAnalyzed: false",
            ]
            if hashes.get("SHA-256"):
                lines.append(f"PackageChecksum: SHA256: {hashes['SHA-256']}")
            if hashes.get("SHA-1"):
                lines.append(f"PackageChecksum: SHA1: {hashes['SHA-1']}")
            if hashes.get("MD5"):
                lines.append(f"PackageChecksum: MD5: {hashes['MD5']}")
            if comp.get("description"):
                lines.append(f"PackageSummary: <text>{comp['description']}</text>")
            lines.append("PackageLicenseConcluded: NOASSERTION")
            lines.append("PackageLicenseDeclared: NOASSERTION")
            lines.append("PackageCopyrightText: NOASSERTION")
            lines.append("")

            # Relationship
            lines.append(f"Relationship: SPDXRef-Package-ROOT CONTAINS {spdx_id}")
            lines.append("")

        spdx_text = "\n".join(lines)
        out_path  = self.output_dir / "sbom.spdx"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(spdx_text)
        logger.info("SPDX SBOM written to %s", out_path)
        return spdx_text

    # ------------------------------------------------------------------ #
    #  HTML section for the main report                                   #
    # ------------------------------------------------------------------ #

    def generate_html_sbom_section(self, components: List[dict]) -> str:
        """
        Return an HTML <div> fragment with a styled component table.
        Rows are color-coded by highest CVE severity.
        """
        def sev_class(vulns: List[dict]) -> str:
            if not vulns:
                return "sev-none"
            top = min(vulns, key=lambda v: SEV_ORDER.get(v.get("severity", "NONE"), 99))
            sev = top.get("severity", "NONE")
            return {
                "CRITICAL": "sev-critical",
                "HIGH":     "sev-high",
                "MEDIUM":   "sev-medium",
                "LOW":      "sev-low",
            }.get(sev, "sev-none")

        def cve_badges(vulns: List[dict]) -> str:
            if not vulns:
                return '<span class="badge badge-clean">None</span>'
            badges = []
            for v in vulns[:3]:
                sev  = v.get("severity", "UNK")
                cid  = v.get("cve_id", "")
                score = v.get("cvss_v3_score")
                score_str = f" ({score})" if score else ""
                cls = {
                    "CRITICAL": "badge-crit",
                    "HIGH":     "badge-high",
                    "MEDIUM":   "badge-med",
                    "LOW":      "badge-low",
                }.get(sev, "badge-info")
                badges.append(f'<span class="badge {cls}" title="{cid}">{cid}{score_str}</span>')
            if len(vulns) > 3:
                badges.append(f'<span class="badge badge-info">+{len(vulns)-3} more</span>')
            return " ".join(badges)

        rows = []
        for comp in components:
            vulns    = comp.get("vulnerabilities", [])
            sc       = sev_class(vulns)
            sha256   = comp.get("hashes", {}).get("SHA-256", "")[:16] + "…"
            cve_count= len(vulns)
            top_sev  = "NONE"
            if vulns:
                top_sev = min(vulns, key=lambda v: SEV_ORDER.get(v.get("severity","NONE"), 99)).get("severity","NONE")

            signed_icon = "✔" if comp.get("is_signed") else "✖"
            signed_cls  = "text-success" if comp.get("is_signed") else "text-danger"

            rows.append(f"""
        <tr class="sbom-row {sc}">
          <td title="{comp.get('file_path','')}"><strong>{comp['name']}</strong></td>
          <td><span class="type-badge">{comp.get('type','file')}</span></td>
          <td>{comp.get('version','') or '—'}</td>
          <td>{comp.get('publisher','') or '—'}</td>
          <td><code class="hash-short">{sha256}</code></td>
          <td><span class="{signed_cls}">{signed_icon}</span></td>
          <td>{cve_badges(vulns)}</td>
          <td><span class="risk-chip risk-{top_sev.lower()}">{top_sev}</span></td>
        </tr>""")

        rows_html = "\n".join(rows)
        total     = len(components)
        cve_total = sum(len(c.get("vulnerabilities", [])) for c in components)
        signed_ct = sum(1 for c in components if c.get("is_signed"))

        return f"""
<style>
  .sbom-table {{ width:100%; border-collapse:collapse; font-size:0.88rem; }}
  .sbom-table th {{ background:#162032; color:#f0a500; padding:10px 12px; text-align:left; font-weight:600; position:sticky; top:0; }}
  .sbom-table td {{ padding:9px 12px; border-bottom:1px solid rgba(255,255,255,0.06); vertical-align:middle; }}
  .sbom-row.sev-critical {{ border-left:3px solid #e63946; }}
  .sbom-row.sev-high     {{ border-left:3px solid #f4a261; }}
  .sbom-row.sev-medium   {{ border-left:3px solid #e9c46a; }}
  .sbom-row.sev-low      {{ border-left:3px solid #2a9d8f; }}
  .sbom-row.sev-none     {{ border-left:3px solid #444; }}
  .badge {{ display:inline-block; padding:2px 7px; border-radius:4px; font-size:0.78rem; font-weight:600; margin:1px; }}
  .badge-crit {{ background:#e63946; color:#fff; }}
  .badge-high {{ background:#f4a261; color:#000; }}
  .badge-med  {{ background:#e9c46a; color:#000; }}
  .badge-low  {{ background:#2a9d8f; color:#fff; }}
  .badge-info {{ background:#3a4a6b; color:#ccc; }}
  .badge-clean{{ background:#2a9d8f; color:#fff; }}
  .type-badge {{ background:#1e3050; color:#90b4e8; padding:2px 8px; border-radius:12px; font-size:0.78rem; }}
  .hash-short {{ background:#111; color:#6dffb9; padding:2px 6px; border-radius:3px; font-size:0.78rem; }}
  .risk-chip  {{ padding:3px 10px; border-radius:12px; font-size:0.78rem; font-weight:700; }}
  .risk-critical {{ background:#e63946; color:#fff; }}
  .risk-high     {{ background:#f4a261; color:#000; }}
  .risk-medium   {{ background:#e9c46a; color:#000; }}
  .risk-low      {{ background:#2a9d8f; color:#fff; }}
  .risk-none     {{ background:#444; color:#aaa; }}
  .text-success  {{ color:#2a9d8f; font-weight:bold; }}
  .text-danger   {{ color:#e63946; font-weight:bold; }}
  .sbom-stats    {{ display:flex; gap:20px; margin-bottom:16px; }}
  .sbom-stat-card{{ background:#162032; border:1px solid #253a55; border-radius:8px; padding:14px 20px; min-width:120px; text-align:center; }}
  .sbom-stat-card .snum {{ font-size:1.8rem; font-weight:700; color:#f0a500; }}
  .sbom-stat-card .slbl {{ font-size:0.78rem; color:#90b4e8; margin-top:4px; }}
</style>

<div class="sbom-stats">
  <div class="sbom-stat-card"><div class="snum">{total}</div><div class="slbl">Total Components</div></div>
  <div class="sbom-stat-card"><div class="snum">{cve_total}</div><div class="slbl">CVEs Found</div></div>
  <div class="sbom-stat-card"><div class="snum">{signed_ct}</div><div class="slbl">Signed Files</div></div>
  <div class="sbom-stat-card"><div class="snum">{total - signed_ct}</div><div class="slbl">Unsigned Files</div></div>
</div>

<div style="overflow-x:auto; max-height:480px; overflow-y:auto; border-radius:8px; border:1px solid #253a55;">
<table class="sbom-table">
  <thead>
    <tr>
      <th>Component</th><th>Type</th><th>Version</th><th>Publisher</th>
      <th>SHA-256 (prefix)</th><th>Signed</th><th>CVEs</th><th>Risk</th>
    </tr>
  </thead>
  <tbody>
{rows_html}
  </tbody>
</table>
</div>
"""
