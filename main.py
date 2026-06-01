#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PSADT-Secure v3.0: Defense-Grade PSADT Package Security Scanner
Enterprise security analysis for aerospace, defense, and critical infrastructure

Compliance: NIST SP 800-53 Rev5 | CMMC 2.0 | IEC 62443-2-4 | CIS Controls v8

Exit codes:
  0  -- APPROVED      (meets all thresholds)
  1  -- REVIEW REQUIRED
  2  -- REJECTED      (critical/high findings above threshold)
  3  -- SCAN ERROR    (exception during scan)
  4  -- MANIFEST INVALID (verify subcommand: signature mismatch)
"""

import sys
import os
import io
import json
import csv
import time

# Fix Windows console encoding for unicode output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import socket
import hashlib
import logging
import argparse
import traceback
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

# --- Add src/ to path first -----------------------------------------------------------
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE / "src"))

# --- Optional crypto for signing ---------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# --- Optional YAML -----------------------------------------------------------------------
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# -----------------------------------------------------------------------------------------

BANNER = """
+==================================================================+
|  PSADT-SECURE v3.0  --  Defense-Grade Package Security Scanner  |
|  NIST 800-53 | CMMC 2.0 | IEC 62443 | CIS v8 | MITRE ATT&CK    |
+==================================================================+
"""

SCANNER_VERSION = "3.0"

# Severity sort order
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# SARIF constants
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


# ---- Logging setup -------------------------------------------------------------------

def _setup_logging(ci_mode: bool) -> logging.Logger:
    level = logging.WARNING if ci_mode else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
        stream=sys.stderr,
    )
    return logging.getLogger("psadt-secure")


# ---- Operator resolution -------------------------------------------------------------

def _resolve_operator(cli_operator: Optional[str]) -> str:
    if cli_operator:
        return cli_operator
    env_op = os.environ.get("PSADT_SCAN_OPERATOR", "")
    if env_op:
        return env_op
    return os.environ.get("USERNAME", socket.gethostname())


# ---- Output directory ----------------------------------------------------------------

def _resolve_output_dir(cli_output: Optional[str], ci_mode: bool = False) -> Path:
    if cli_output:
        return Path(cli_output)
    if ci_mode:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Path.cwd() / f"psadt_scan_{ts}"
    
    try:
        name = input("\n[?] Enter the name for the report folder (will be saved in C:\\SecurePSADT\\<name>): ").strip()
    except EOFError:
        name = ""
        
    if not name:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"psadt_scan_{ts}"
        
    return Path("C:\\SecurePSADT") / name


# ---- Allowlist loader ----------------------------------------------------------------

def _load_allowlist(allowlist_path: Optional[str]) -> dict:
    if not allowlist_path:
        return {}
    p = Path(allowlist_path)
    if not p.exists():
        print(f"[!] Allowlist file not found: {p}", file=sys.stderr)
        return {}
    if not YAML_AVAILABLE:
        print("[!] PyYAML not installed; allowlist ignored.", file=sys.stderr)
        return {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data or {}
    except Exception as exc:
        print(f"[!] Could not load allowlist: {exc}", file=sys.stderr)
        return {}


# ---- Allowlist filtering -------------------------------------------------------------

def _apply_allowlist(findings: dict, allowlist: dict) -> dict:
    """Remove findings that are covered by a valid, non-expired allowlist exception."""
    if not allowlist or not allowlist.get("exceptions"):
        return findings

    never = set(allowlist.get("never_allowlist", []))
    exceptions = allowlist.get("exceptions", []) or []
    today = datetime.now(timezone.utc).date()

    suppressed = []
    surviving_issues = []

    for issue in findings.get("issues", []):
        rule_id = issue.get("subtype") or issue.get("pattern") or ""
        if rule_id in never:
            surviving_issues.append(issue)
            continue

        matched = False
        for exc in exceptions:
            # Validate exception structure
            if not all(k in exc for k in ("rule_id", "expiry", "ticket")):
                continue
            # Expired?
            try:
                expiry = datetime.strptime(str(exc["expiry"]), "%Y-%m-%d").date()
            except Exception:
                continue
            if expiry < today:
                continue
            # Rule match
            if exc.get("rule_id") != rule_id:
                continue
            # File pattern match
            fp = exc.get("file_pattern", "")
            if fp and fp not in issue.get("file", ""):
                continue
            # Optional match_contains
            mc = exc.get("match_contains", "")
            if mc and mc not in issue.get("match", ""):
                continue
            # All checks passed
            matched = True
            issue["allowlisted"] = True
            issue["allowlist_ticket"] = exc.get("ticket", "")
            issue["allowlist_id"] = exc.get("id", "")
            suppressed.append(issue)
            break

        if not matched:
            surviving_issues.append(issue)

    findings["issues"] = surviving_issues
    findings["allowlisted_issues"] = suppressed
    # Recount summary
    for sev in ("critical", "high", "medium", "low"):
        findings["summary"][sev] = sum(
            1 for i in surviving_issues
            if i.get("severity", "").lower() == sev
        )
    findings["summary"]["total_issues"] = len(surviving_issues)
    return findings


# ---- SARIF export --------------------------------------------------------------------

def _export_sarif(findings: dict, output_dir: Path):
    """Export findings as SARIF 2.1.0 JSON."""
    rules = {}
    results = []

    for issue in findings.get("issues", []):
        rule_id  = issue.get("subtype") or issue.get("pattern") or "unknown"
        severity = issue.get("severity", "LOW")

        sarif_level = {
            "CRITICAL": "error",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
        }.get(severity, "note")

        if rule_id not in rules:
            rules[rule_id] = {
                "id":   rule_id,
                "name": rule_id,
                "shortDescription": {"text": issue.get("pattern", rule_id)},
                "helpUri": f"https://github.com/psadt-secure/wiki/{rule_id}",
                "properties": {
                    "tags": [severity],
                    "security-severity": {
                        "CRITICAL": "9.0", "HIGH": "7.0",
                        "MEDIUM": "5.0", "LOW": "3.0"
                    }.get(severity, "3.0"),
                },
            }

        file_path = issue.get("file", "")
        line_num  = issue.get("line", 1) or 1

        results.append({
            "ruleId":  rule_id,
            "level":   sarif_level,
            "message": {"text": issue.get("match", issue.get("pattern", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(file_path).name},
                    "region": {
                        "startLine": int(line_num),
                        "snippet":   {"text": (issue.get("context") or "")[:200]},
                    },
                }
            }],
            "properties": {
                "confidence":   issue.get("confidence", 0),
                "mitre":        issue.get("mitre_id", ""),
                "cwe":          issue.get("cwe_id", ""),
                "remediation":  issue.get("remediation", ""),
            },
        })

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "PSADTSecureScanner",
                    "version": SCANNER_VERSION,
                    "rules":   list(rules.values()),
                    "informationUri": "https://github.com/psadt-secure",
                }
            },
            "results": results,
        }],
    }
    out = output_dir / "findings.sarif.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sarif_doc, fh, indent=2)
    return out


# ---- JUnit XML export ---------------------------------------------------------------

def _export_junit(findings: dict, output_dir: Path):
    """Export findings as JUnit XML (CI/CD integration)."""
    issues = findings.get("issues", [])
    summary = findings.get("summary", {})
    ts = datetime.now(timezone.utc).isoformat()

    failures = sum(1 for i in issues if i.get("severity") in ("CRITICAL", "HIGH"))
    errors   = summary.get("critical", 0)

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="PSADTSecureScan" tests="{len(issues)}" '
        f'failures="{failures}" errors="{errors}" timestamp="{ts}">',
        f'  <testsuite name="SecurityFindings" tests="{len(issues)}" '
        f'failures="{failures}" errors="{errors}">',
    ]
    for issue in issues:
        name = issue.get("pattern", "unknown").replace('"', "&quot;")
        sev  = issue.get("severity", "LOW")
        file_ = Path(issue.get("file", "")).name.replace('"', "&quot;")
        line  = issue.get("line", 0)
        rem   = (issue.get("remediation", "") or "").replace("<", "&lt;").replace(">", "&gt;")
        match = (issue.get("match", "") or "")[:200].replace("<", "&lt;").replace(">", "&gt;")

        lines.append(f'    <testcase name="{name}" classname="{file_}" time="0">')
        if sev in ("CRITICAL", "HIGH"):
            lines.append(f'      <failure type="{sev}" message="{match}">')
            lines.append(f'        File: {file_}, Line: {line}')
            lines.append(f'        Remediation: {rem}')
            lines.append(f'      </failure>')
        elif sev == "MEDIUM":
            lines.append(f'      <error type="{sev}" message="{match}"/>')
        lines.append("    </testcase>")

    lines += ["  </testsuite>", "</testsuites>"]
    out = output_dir / "findings.junit.xml"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out


# ---- Cryptographic signing -----------------------------------------------------------

def _sign_manifest(output_dir: Path, key_path: Optional[str], logger) -> bool:
    """Generate manifest.json, sign with ECDSA P-384, write manifest.sig and public key."""
    if not CRYPTO_AVAILABLE:
        logger.error("cryptography library not installed; cannot sign manifest.")
        return False

    # Load or generate key
    if key_path and Path(key_path).exists():
        try:
            with open(key_path, "rb") as fh:
                private_key = serialization.load_pem_private_key(fh.read(), password=None)
            logger.info("Loaded signing key from %s", key_path)
        except Exception as exc:
            logger.error("Could not load signing key %s: %s", key_path, exc)
            return False
    else:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        if key_path:
            ephemeral_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(key_path, "wb") as fh:
                fh.write(ephemeral_pem)
            logger.info("Ephemeral ECDSA key saved to %s", key_path)
        else:
            logger.info("Using ephemeral ECDSA P-384 key (not persisted).")

    public_key = private_key.public_key()

    # Build manifest: hashes of all output files
    manifest: Dict[str, str] = {}
    for f in sorted(output_dir.iterdir()):
        if f.is_file() and f.name not in ("manifest.json", "manifest.sig", "manifest_public.pem"):
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            manifest[f.name] = sha256

    manifest_path = output_dir / "manifest.json"
    manifest_bytes = json.dumps({"files": manifest, "generated": datetime.now(timezone.utc).isoformat()},
                                 indent=2, sort_keys=True).encode("utf-8")
    with open(manifest_path, "wb") as fh:
        fh.write(manifest_bytes)

    # Sign
    signature = private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA384()))
    with open(output_dir / "manifest.sig", "wb") as fh:
        fh.write(signature)

    # Write public key
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(output_dir / "manifest_public.pem", "wb") as fh:
        fh.write(pub_pem)

    logger.info("Manifest signed. Files: manifest.json, manifest.sig, manifest_public.pem")
    return True


# ---- Verify manifest -----------------------------------------------------------------

def _verify_manifest(manifest_dir: Path, logger) -> bool:
    """Verify the ECDSA manifest signature. Returns True if valid."""
    if not CRYPTO_AVAILABLE:
        print("[!] cryptography library not installed; cannot verify.", file=sys.stderr)
        return False

    manifest_path = manifest_dir / "manifest.json"
    sig_path      = manifest_dir / "manifest.sig"
    pub_path      = manifest_dir / "manifest_public.pem"

    for p in (manifest_path, sig_path, pub_path):
        if not p.exists():
            print(f"[!] Missing: {p}", file=sys.stderr)
            return False

    manifest_bytes = manifest_path.read_bytes()
    signature_bytes = sig_path.read_bytes()
    pub_pem = pub_path.read_bytes()

    try:
        public_key = serialization.load_pem_public_key(pub_pem)
        public_key.verify(signature_bytes, manifest_bytes, ec.ECDSA(hashes.SHA384()))
    except Exception as exc:
        print(f"[✗] Signature INVALID: {exc}", file=sys.stderr)
        return False

    # Also verify file hashes
    manifest_data = json.loads(manifest_bytes)
    all_ok = True
    for fname, expected_hash in manifest_data.get("files", {}).items():
        fpath = manifest_dir / fname
        if not fpath.exists():
            print(f"[!] File listed in manifest not found: {fname}", file=sys.stderr)
            all_ok = False
            continue
        actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual != expected_hash:
            print(f"[✗] Hash mismatch for {fname}", file=sys.stderr)
            all_ok = False

    return all_ok


# ---- Print results summary -----------------------------------------------------------

def _print_summary(findings: dict, output_dir: Path, ci_mode: bool):
    summary = findings.get("summary", {})
    status  = summary.get("approval_status", "UNKNOWN")

    if ci_mode:
        print(json.dumps({
            "status":      status,
            "risk_score":  findings.get("risk_score", 0),
            "critical":    summary.get("critical", 0),
            "high":        summary.get("high", 0),
            "medium":      summary.get("medium", 0),
            "low":         summary.get("low", 0),
            "total":       summary.get("total_issues", 0),
            "output_dir":  str(output_dir),
        }))
        return

    print("\n" + "═" * 65)
    print("  PSADT-SECURE v3.0 — SCAN RESULTS")
    print("═" * 65)
    print(f"  Package    : {findings.get('package', 'Unknown')}")
    print(f"  Risk Score : {findings.get('risk_score', 0):.1f}/100")
    print(f"  Status     : {status}")
    print()
    print(f"  🔴 CRITICAL : {summary.get('critical', 0)}")
    print(f"  🟠 HIGH     : {summary.get('high', 0)}")
    print(f"  🟡 MEDIUM   : {summary.get('medium', 0)}")
    print(f"  🔵 LOW      : {summary.get('low', 0)}")
    print(f"  Total      : {summary.get('total_issues', 0)}")
    print()
    print(f"  Duration   : {summary.get('scan_duration', 0):.2f}s")
    print(f"  Output     : {output_dir}")

    # Top 5 issues
    issues = sorted(findings.get("issues", []), key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 99))
    if issues:
        print("\n  [!] DEVELOPER ACTION:")
        print(f"      To see the EXACT location of these risks, open: {output_dir / 'report.html'}")
        print("\n  TOP FINDINGS:")
        for issue in issues[:5]:
            sev     = issue.get("severity", "LOW")
            pattern = issue.get("pattern", "Unknown")
            file_   = Path(issue.get("file", "")).name
            line_   = issue.get("line", "?")
            print(f"    [{sev:8s}] {pattern} — {file_}:{line_}")
            rem = issue.get("remediation", "")
            if rem:
                print(f"             ↳ {rem[:70]}")

    print("═" * 65)
    if status == "APPROVED":
        print("  ✔  PACKAGE APPROVED FOR DEPLOYMENT")
    elif status == "REVIEW_REQUIRED":
        print("  ⚠  PACKAGE REQUIRES SECURITY REVIEW")
    else:
        print("  ✖  PACKAGE REJECTED — REMEDIATION REQUIRED")
    print("═" * 65 + "\n")


# ---- Determine exit code ------------------------------------------------------------

def _exit_code(findings: dict, fail_on: List[str]) -> int:
    status = findings.get("summary", {}).get("approval_status", "REVIEW_REQUIRED")
    summary = findings.get("summary", {})

    if status == "APPROVED":
        # Even if status is approved, respect --fail-on
        for sev in fail_on:
            if summary.get(sev.lower(), 0) > 0:
                return 2
        return 0
    elif status == "REVIEW_REQUIRED":
        for sev in fail_on:
            if summary.get(sev.lower(), 0) > 0:
                return 2
        return 1
    else:  # REJECTED
        return 2


# ---- Subcommand: scan ---------------------------------------------------------------

def cmd_scan(args, logger) -> int:
    from scanners.scan_psadt import PSADTSecureScanner

    package_path = Path(args.package_path)
    if not package_path.is_dir():
        print(f"[✖] Package directory not found: {package_path}", file=sys.stderr)
        return 3

    output_dir = _resolve_output_dir(args.output_dir, args.ci)
    output_dir.mkdir(parents=True, exist_ok=True)

    operator = _resolve_operator(args.operator)
    nvd_key  = args.nvd_api_key or os.environ.get("NVD_API_KEY", "")
    formats  = [f.strip() for f in args.format.split(",")]
    if "all" in formats:
        formats = ["html", "json", "csv", "sarif", "junit", "sbom"]
    fail_on  = [f.strip().upper() for f in (args.fail_on or "critical,high").split(",")]

    if not args.ci:
        print(BANNER)
        print(f"  Package   : {package_path}")
        print(f"  Output    : {output_dir}")
        print(f"  Operator  : {operator}")
        print(f"  Formats   : {', '.join(formats)}")
        print(f"  Fail-on   : {', '.join(fail_on)}")
        print(f"  Network   : {'OFFLINE' if args.no_network else 'ONLINE'}")
        print()

    try:
        # --- Step 1: Core scan ---
        if not args.ci:
            print("[1/5] Running security scan...")

        scanner = PSADTSecureScanner(str(package_path), str(output_dir))
        scanner.findings["operator"] = operator
        scanner.findings["scanner_version"] = f"{scanner.findings.get('scanner_version', '')} (CLI v{SCANNER_VERSION})"

        findings = scanner.scan()

        # --- Step 2: Apply allowlist ---
        allowlist = {}
        if args.allowlist:
            if not args.ci:
                print("[2/5] Applying allowlist exceptions...")
            allowlist = _load_allowlist(args.allowlist)
            findings  = _apply_allowlist(findings, allowlist)
            # Recompute approval status after allowlist suppression
            if not args.ci:
                suppressed = len(findings.get("allowlisted_issues", []))
                if suppressed:
                    print(f"      ↳ {suppressed} finding(s) suppressed by allowlist.")

        # --- Step 3: Severity threshold check ---
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = sev_map.get((args.severity_threshold or "HIGH").upper(), 1)
        relevant_issues = [
            i for i in findings.get("issues", [])
            if sev_map.get(i.get("severity", "LOW"), 99) <= threshold
        ]
        # Override approval status based on threshold
        if any(i.get("severity", "") in ("CRITICAL", "HIGH") for i in relevant_issues):
            findings["summary"]["approval_status"] = "REJECTED"
        elif any(i.get("severity", "") == "MEDIUM" for i in relevant_issues):
            findings["summary"]["approval_status"] = "REVIEW_REQUIRED"

        # --- Step 4: SBOM generation ---
        sbom_data = {}
        if not args.no_network and ("sbom" in formats or "all" in formats or "html" in formats):
            if not args.ci:
                print("[3/5] Generating SBOM...")
            try:
                from scanners.sbom_generator import SBOMGenerator
                sbom_gen  = SBOMGenerator(package_path, output_dir, nvd_key)
                sbom_data = sbom_gen.generate()
                findings["sbom_summary"] = {
                    "components":  sbom_data.get("component_count", 0),
                    "total_cves":  sbom_data.get("total_cves", 0),
                    "cyclonedx":   str(output_dir / "sbom.cyclonedx.json"),
                    "spdx":        str(output_dir / "sbom.spdx"),
                }
            except Exception as exc:
                logger.warning("SBOM generation failed: %s", exc)
                if not args.ci:
                    print(f"      [!] SBOM generation failed: {exc}")
        else:
            if not args.ci:
                print("[3/5] Skipping SBOM (--no-network or format not requested).")

        # --- Step 5: Report generation ---
        if not args.ci:
            print("[4/5] Generating reports...")

        report_files = []

        # JSON (always generated by scanner, but re-write with enriched data)
        if "json" in formats:
            json_path = output_dir / "findings.json"
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(findings, fh, indent=2, default=str)
            report_files.append(str(json_path))

        # CSV
        if "csv" in formats:
            csv_path = output_dir / "findings.csv"
            fieldnames = ["Severity", "Type", "File", "Line", "Pattern", "Match",
                          "Remediation", "MITRE", "CWE", "Confidence", "Allowlisted"]
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for issue in findings.get("issues", []):
                    writer.writerow({
                        "Severity":     issue.get("severity", ""),
                        "Type":         issue.get("type", ""),
                        "File":         Path(issue.get("file", "")).name,
                        "Line":         issue.get("line", ""),
                        "Pattern":      issue.get("pattern", ""),
                        "Match":        (issue.get("match") or "")[:100],
                        "Remediation":  (issue.get("remediation") or "")[:150],
                        "MITRE":        issue.get("mitre_id", ""),
                        "CWE":          issue.get("cwe_id", ""),
                        "Confidence":   issue.get("confidence", ""),
                        "Allowlisted":  issue.get("allowlisted", False),
                    })
            report_files.append(str(csv_path))

        # HTML
        if "html" in formats:
            if not args.ci:
                print("      Generating HTML report...")
            try:
                from scanners.report_generator import ReportGenerator
                workflow_summary = {}
                wf_path = output_dir / "workflow_state.json"
                if wf_path.exists():
                    try:
                        from scanners.approval_workflow import ApprovalWorkflow
                        wf = ApprovalWorkflow(package_path, output_dir)
                        workflow_summary = wf.get_workflow_summary()
                    except Exception:
                        pass
                rg = ReportGenerator(findings, sbom_data=sbom_data, workflow=workflow_summary)
                html_path = output_dir / "report.html"
                rg.generate_html(html_path)
                report_files.append(str(html_path))
            except Exception as exc:
                logger.error("HTML report generation failed: %s", exc)
                if not args.ci:
                    print(f"      [!] HTML report failed: {exc}")

        # SARIF
        if "sarif" in formats:
            sarif_path = _export_sarif(findings, output_dir)
            report_files.append(str(sarif_path))

        # JUnit
        if "junit" in formats:
            junit_path = _export_junit(findings, output_dir)
            report_files.append(str(junit_path))

        # --- Step 5b: Approval workflow bootstrap ---
        if not args.ci:
            print("[4/5] Recording workflow state...")
        try:
            from scanners.approval_workflow import ApprovalWorkflow
            wf = ApprovalWorkflow(package_path, output_dir)
            if wf._state.get("current_state") == "PENDING_SCAN":
                wf.record_scan_result(findings)
        except Exception as exc:
            logger.warning("Workflow state recording failed: %s", exc)

        # --- Step 5c: Sign manifest ---
        if args.sign_report:
            if not args.ci:
                print("[5/5] Signing report manifest...")
            _sign_manifest(output_dir, args.signing_key, logger)
        else:
            if not args.ci:
                print("[5/5] (Manifest signing skipped; use --sign-report to enable)")

        # --- Print summary ---
        _print_summary(findings, output_dir, args.ci)

        if not args.ci:
            print("  Generated reports:")
            for rp in report_files:
                print(f"    ├─ {Path(rp).name}")
            print()

        return _exit_code(findings, fail_on)

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"\n[✖] SCAN ERROR: {exc}", file=sys.stderr)
        if not args.ci:
            traceback.print_exc()
        return 3


# ---- Subcommand: verify -------------------------------------------------------------

def cmd_verify(args, logger) -> int:
    manifest_dir = Path(args.manifest_dir)
    if not manifest_dir.is_dir():
        print(f"[✖] Directory not found: {manifest_dir}", file=sys.stderr)
        return 4

    print(f"\n[*] Verifying manifest in: {manifest_dir}")
    valid = _verify_manifest(manifest_dir, logger)

    if valid:
        print("[✔] Manifest signature VALID — all file hashes match.")
        return 0
    else:
        print("[✖] Manifest signature INVALID or file hashes mismatched.")
        return 4


# ---- Subcommand: workflow ------------------------------------------------------------

def cmd_workflow(args, logger) -> int:
    try:
        from scanners.approval_workflow import ApprovalWorkflow
    except ImportError as exc:
        print(f"[✖] Could not import ApprovalWorkflow: {exc}", file=sys.stderr)
        return 3

    action = args.workflow_action

    if action == "analyst-review":
        scan_dir = Path(args.scan_dir)
        if not scan_dir.is_dir():
            print(f"[✖] Scan directory not found: {scan_dir}", file=sys.stderr)
            return 3

        # Load findings to build disposition skeleton
        findings_path = scan_dir / "findings.json"
        disposition: Dict[str, dict] = {}
        if findings_path.exists():
            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
                decision = "ACCEPTED_RISK" if args.approve else "TP"
                for idx, issue in enumerate(findings.get("issues", [])):
                    finding_id = f"finding-{idx:04d}"
                    disposition[finding_id] = {
                        "status": decision,
                        "notes":  args.notes or "",
                    }
            except Exception as exc:
                logger.warning("Could not load findings.json: %s", exc)

        if not disposition and (args.approve or args.reject):
            disposition["global"] = {
                "status": "ACCEPTED_RISK" if args.approve else "TP",
                "notes":  args.notes or "",
            }

        try:
            wf = ApprovalWorkflow(Path(args.scan_dir), scan_dir)
            new_state = wf.analyst_review(
                analyst_name=args.analyst_name,
                disposition=disposition,
                notes=args.notes or "",
            )
            print(f"[✔] Analyst review recorded. New state: {new_state}")
            return 0
        except Exception as exc:
            print(f"[✖] Analyst review failed: {exc}", file=sys.stderr)
            return 3

    elif action == "ciso-approve":
        scan_dir = Path(args.scan_dir)
        if not scan_dir.is_dir():
            print(f"[✖] Scan directory not found: {scan_dir}", file=sys.stderr)
            return 3

        decision = "APPROVE" if args.approve else "REJECT"
        try:
            wf = ApprovalWorkflow(Path(args.scan_dir), scan_dir)
            new_state = wf.ciso_approval(
                ciso_name=args.ciso_name,
                decision=decision,
                authorization_number=args.authorization_number,
                notes=args.notes or "",
            )
            print(f"[✔] CISO {decision} recorded. New state: {new_state}")
            if new_state == "CISO_APPROVED":
                auth_path = scan_dir / "deployment_authorization.json"
                if auth_path.exists():
                    print(f"    Authorization: {auth_path}")
            return 0
        except Exception as exc:
            print(f"[✖] CISO approval failed: {exc}", file=sys.stderr)
            return 3

    else:
        print(f"[✖] Unknown workflow action: {action}", file=sys.stderr)
        return 3


# ---- Argument parser ----------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psadt-secure",
        description=(
            "PSADT-Secure v3.0 — Defense-Grade PSADT Package Security Scanner\n"
            "Compliance: NIST SP 800-53 Rev5 | CMMC 2.0 | IEC 62443-2-4 | CIS Controls v8"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  APPROVED         (meets all thresholds)
  1  REVIEW REQUIRED
  2  REJECTED         (critical/high above fail-on threshold)
  3  SCAN ERROR
  4  MANIFEST INVALID (verify subcommand only)

Examples:
  # Basic scan
  python main.py scan C:\\Packages\\MyApp

  # Full enterprise scan with all outputs and SBOM
  python main.py scan C:\\Packages\\MyApp -o C:\\Reports\\MyApp -f all --sign-report

  # CI/CD mode (JSON to stdout, minimal noise)
  python main.py scan C:\\Packages\\MyApp --ci --fail-on critical,high

  # Verify signed manifest
  python main.py verify C:\\Reports\\MyApp

  # Analyst review (approve)
  python main.py workflow analyst-review C:\\Reports\\MyApp Jane.Smith --approve --notes "All FPs validated"

  # CISO approval
  python main.py workflow ciso-approve C:\\Reports\\MyApp CEO.Name AUTH-20260601 --approve
""",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ---- scan subcommand ----
    scan_p = sub.add_parser(
        "scan",
        help="Scan a PSADT package",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_p.add_argument(
        "package_path",
        metavar="PACKAGE_PATH",
        help="Path to the PSADT package directory to scan",
    )
    scan_p.add_argument(
        "--output-dir", "-o",
        dest="output_dir",
        metavar="DIR",
        default=None,
        help="Output directory for reports (default: psadt_scan_TIMESTAMP in current dir)",
    )
    scan_p.add_argument(
        "--format", "-f",
        dest="format",
        metavar="FORMAT",
        default="html,json,csv",
        help="Output formats: html,json,csv,sarif,junit,sbom,all (comma-separated; default: html,json,csv)",
    )
    scan_p.add_argument(
        "--compliance",
        dest="compliance",
        choices=["nist", "cmmc", "iec62443", "cis", "all"],
        default="all",
        help="Compliance framework filter (default: all)",
    )
    scan_p.add_argument(
        "--severity-threshold",
        dest="severity_threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Issues below this severity do not affect approval (default: HIGH)",
    )
    scan_p.add_argument(
        "--allowlist",
        dest="allowlist",
        metavar="FILE",
        default=None,
        help="Path to allowlist.yaml for exception management",
    )
    scan_p.add_argument(
        "--operator",
        dest="operator",
        metavar="NAME",
        default=None,
        help="Operator name for audit log (fallback: PSADT_SCAN_OPERATOR env var, then hostname)",
    )
    scan_p.add_argument(
        "--nvd-api-key",
        dest="nvd_api_key",
        metavar="KEY",
        default=None,
        help="NVD API key for SBOM CVE lookups (fallback: NVD_API_KEY env var)",
    )
    scan_p.add_argument(
        "--no-network",
        dest="no_network",
        action="store_true",
        default=False,
        help="Offline mode: skip CVE/OCSP/NVD network lookups",
    )
    scan_p.add_argument(
        "--sign-report",
        dest="sign_report",
        action="store_true",
        default=False,
        help="Generate ECDSA-signed manifest for report integrity verification",
    )
    scan_p.add_argument(
        "--signing-key",
        dest="signing_key",
        metavar="PEM",
        default=None,
        help="Path to ECDSA private key PEM (if omitted, ephemeral key generated)",
    )
    scan_p.add_argument(
        "--ci",
        dest="ci",
        action="store_true",
        default=False,
        help="CI/CD mode: JSON-only to stdout, minimal console output",
    )
    scan_p.add_argument(
        "--fail-on",
        dest="fail_on",
        metavar="SEVERITIES",
        default="critical,high",
        help="Comma-separated severity levels that cause non-zero exit (default: critical,high)",
    )

    # ---- verify subcommand ----
    verify_p = sub.add_parser(
        "verify",
        help="Verify a signed report manifest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify_p.add_argument(
        "manifest_dir",
        metavar="DIR",
        help="Directory containing manifest.json, manifest.sig, and manifest_public.pem",
    )

    # ---- workflow subcommand ----
    wf_p = sub.add_parser(
        "workflow",
        help="Manage approval workflow stages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    wf_sub = wf_p.add_subparsers(dest="workflow_action", metavar="ACTION")
    wf_sub.required = True

    # analyst-review
    ar_p = wf_sub.add_parser("analyst-review", help="Record analyst review disposition")
    ar_p.add_argument("scan_dir",     metavar="SCAN_DIR",  help="Scan output directory")
    ar_p.add_argument("analyst_name", metavar="ANALYST",   help="Analyst full name")
    ar_p.add_argument("--approve", dest="approve", action="store_true", default=False,
                      help="Mark all findings as FP/ACCEPTED_RISK (approve)")
    ar_p.add_argument("--reject",  dest="reject",  action="store_true", default=False,
                      help="Confirm all remaining findings as TP (reject)")
    ar_p.add_argument("--notes",   dest="notes",   metavar="TEXT", default="",
                      help="Analyst review notes")

    # ciso-approve
    ca_p = wf_sub.add_parser("ciso-approve", help="Record CISO approval decision")
    ca_p.add_argument("scan_dir",             metavar="SCAN_DIR",   help="Scan output directory")
    ca_p.add_argument("ciso_name",            metavar="CISO",       help="CISO full name")
    ca_p.add_argument("authorization_number", metavar="AUTH_NUM",   help="Authorization reference number")
    ca_p.add_argument("--approve", dest="approve", action="store_true", default=False,
                      help="Approve deployment")
    ca_p.add_argument("--reject",  dest="reject",  action="store_true", default=False,
                      help="Reject deployment")
    ca_p.add_argument("--notes",   dest="notes",   metavar="TEXT",  default="",
                      help="CISO review notes")

    return parser


# ---- Entry point --------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args   = parser.parse_args()

    ci_mode = getattr(args, "ci", False)
    logger  = _setup_logging(ci_mode)

    if not ci_mode and args.command == "scan":
        print(BANNER)

    if args.command == "scan":
        return cmd_scan(args, logger)
    elif args.command == "verify":
        return cmd_verify(args, logger)
    elif args.command == "workflow":
        return cmd_workflow(args, logger)
    else:
        parser.print_help()
        return 3


if __name__ == "__main__":
    sys.exit(main())
