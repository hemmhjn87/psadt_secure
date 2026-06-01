# PSADT-Secure v3.0 — SBOM Guide

> **Document**: Software Bill of Materials Guide  
> **Version**: 3.0.0  
> **Standards**: NTIA SBOM Minimum Elements, CycloneDX 1.4, SPDX 2.3, NIST SP 800-161r1

---

## 1. What is an SBOM?

A **Software Bill of Materials (SBOM)** is a formal, structured list of all software components, libraries, and dependencies in a software package. Think of it as the nutritional label for software — it tells you exactly what is inside.

For PSADT packages, this means every:
- Executable (`.exe`, `.dll`, `.sys`)
- Installer package (`.msi`, `.msp`, `.msix`)
- Script file (`.ps1`, `.psm1`, `.bat`, `.cmd`)
- Configuration file (`.xml`, `.json`, `.ini`)
- Any other file bundled in the package

---

## 2. Why SBOMs Matter for Aerospace/Defense

| Requirement | Context |
|-------------|---------|
| **Executive Order 14028** | US federal agencies must require SBOMs from software vendors |
| **NIST SP 800-161r1** | C-SCRM — supply chain risk management requires component visibility |
| **CMMC 2.0 SA.4.171** | "Use static code analysis tools" — SBOM is part of secure development |
| **Boeing BSPS** | Component provenance required for all third-party software |
| **Safran DSP-SEC-001** | SBOM retained for 5 years; CVE status monitored continuously |
| **IEC 62443-2-4** | SR 3.2 — malicious code protection requires knowing what's present |

---

## 3. SBOM Formats Generated

### CycloneDX 1.4 (`sbom.cyclonedx.json`)

Industry-standard format, natively supported by:
- OWASP Dependency-Track
- Anchore Grype
- Snyk
- JFrog Xray
- GitHub Dependency Graph

Structure:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2026-06-01T00:00:00Z",
    "tools": [{"vendor": "PSADT-Secure", "name": "PSADTSecureScanner", "version": "3.0"}],
    "component": {"type": "application", "name": "PackageName"}
  },
  "components": [
    {
      "type": "library",
      "name": "setup.exe",
      "version": "1.2.3.0",
      "publisher": "Vendor Corp",
      "hashes": [
        {"alg": "MD5", "content": "abc123..."},
        {"alg": "SHA-256", "content": "def456..."},
        {"alg": "SHA-512", "content": "ghi789..."}
      ],
      "properties": [
        {"name": "authenticode_signed", "value": "true"},
        {"name": "entropy", "value": "5.82"},
        {"name": "file_type", "value": "PE32+"}
      ],
      "vulnerabilities": [
        {
          "id": "CVE-2024-XXXXX",
          "ratings": [{"score": 7.8, "severity": "high", "method": "CVSSv31"}]
        }
      ]
    }
  ]
}
```

### SPDX 2.3 (`sbom.spdx`)

Tag-value format, preferred by Linux Foundation and automotive/aerospace supply chains:
```
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: PackageName-SBOM
DocumentNamespace: urn:psadt-secure:PackageName:...

PackageName: setup.exe
SPDXID: SPDXRef-setup-exe
PackageVersion: 1.2.3.0
PackageSupplier: Organization: Vendor Corp
PackageDownloadLocation: NOASSERTION
FileChecksum: SHA256: def456...
FileChecksum: SHA1: abc123...
```

---

## 4. Reading the SBOM Report

### HTML Report SBOM Section

The HTML report includes a SBOM inventory table with these columns:

| Column | Description |
|--------|-------------|
| **Component** | File name |
| **Type** | PE32/PE64/Script/MSI/Other |
| **Version** | Extracted from PE headers or MSI properties |
| **Publisher** | Company name from PE headers |
| **SHA-256** | File hash (first 16 chars shown) |
| **Signed** | ✅ Valid / ⚠️ Invalid / ❌ Unsigned |
| **CVEs** | Number of known vulnerabilities |
| **Risk** | Derived from highest CVE CVSS score |

Row colors:
- 🔴 **Red**: CVEs with CRITICAL severity (CVSS ≥ 9.0)
- 🟠 **Orange**: CVEs with HIGH severity (CVSS 7.0–8.9)
- 🟡 **Yellow**: CVEs with MEDIUM severity (CVSS 4.0–6.9)
- 🟢 **Green**: No known CVEs
- ⚪ **Gray**: Component not found in NVD (not necessarily safe)

---

## 5. CVE Triage Workflow

When the SBOM shows CVEs, follow this triage process:

```
CVE Found in SBOM
       │
       ▼
1. Check CVE details: Is it exploitable in this context?
   - Attack Vector: LOCAL (reduced risk in isolated package)
   - User Interaction: REQUIRED (mitigated by admin deployment)
   - AV = NETWORK + UI = NONE → Higher concern
       │
       ├── NOT exploitable in deployment context
       │   → Document as "Accepted Risk" in allowlist
       │   → Note: even if not exploitable, track and remediate on next package update
       │
       └── POTENTIALLY exploitable
               │
               ▼
       2. Check if vendor patch available
               │
               ├── PATCH AVAILABLE → Update component; re-scan
               │
               └── NO PATCH → Escalate to CISO
                   Options:
                   a) Deploy with compensating controls + monitoring
                   b) Reject package until vendor patches
                   c) Replace component with alternative
```

### CVSS Contextual Scoring for Package Context

PSADT packages are typically deployed by SCCM/Intune from privileged context. Consider these context modifiers:

| CVE Vector | Deployment Context | Effective Risk |
|------------|-------------------|----------------|
| AV:N (Network) + high CVSS | Executed by SYSTEM during deploy | HIGH — attacker could exploit pre-deploy |
| AV:L (Local) | Local execution required | LOWER — but still assess |
| PR:H (High Privileges Required) | Package runs as SYSTEM | VARIES — attacker needs SYSTEM first |
| UI:R (User Interaction) | Silent install = no UI | LOWER for UI-based exploits |

---

## 6. SBOM Retention Requirements

| Organization Type | SBOM Retention |
|------------------|----------------|
| Standard Enterprise | 2 years |
| Aerospace / Defense | 5 years (Safran DSP-SEC-001) |
| DoD / CMMC | 3 years minimum |
| Safety-Critical (IEC 62443) | Product lifetime |

Store SBOMs in:
- Version control system (recommended: same repo as package, tagged release)
- Document management system with access controls
- SBOM management platform (e.g., OWASP Dependency-Track)

---

## 7. Integrating with OWASP Dependency-Track

OWASP Dependency-Track is a free, open-source SBOM management platform:

```powershell
# Upload SBOM to Dependency-Track after scan
$DTrackUrl = "https://dependency-track.internal.corp.com"
$ApiKey = $env:DTRACK_API_KEY

$body = @{
    projectName = "PSADT-" + $PackageName
    projectVersion = $PackageVersion
    autoCreate = "true"
    bom = [Convert]::ToBase64String([IO.File]::ReadAllBytes("sbom.cyclonedx.json"))
}

Invoke-RestMethod -Uri "$DTrackUrl/api/v1/bom" `
    -Method PUT `
    -Headers @{"X-Api-Key" = $ApiKey; "Content-Type" = "application/json"} `
    -Body ($body | ConvertTo-Json)
```

Benefits:
- Continuous monitoring: Alerts when new CVEs affect your inventory
- Dashboard: See all packages and their CVE status at a glance
- Policy gates: Automatically flag packages with critical CVEs

---

## 8. Offline Mode (Air-Gapped Environments)

For environments without internet access:

```powershell
# Run with --no-network flag
python main.py scan <path> --no-network

# SBOM will be generated without CVE data
# Components will show "CVE status: Unknown (offline mode)"
```

**For air-gapped environments, maintain a local NVD database:**

1. Download NVD JSON feeds weekly on an internet-connected system:
   ```powershell
   # Download NVD data feeds (from connected system)
   $year = (Get-Date).Year
   Invoke-WebRequest "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$year.json.gz" -OutFile "nvdcve-$year.json.gz"
   # Transfer to air-gapped system via approved transfer mechanism
   ```

2. Import into PSADT-Secure local cache:
   ```powershell
   python main.py update-nvd-cache --input "nvdcve-2026.json.gz"
   ```

---

*SBOM Guide maintained by: Security Operations*  
*Standards Reference: NTIA SBOM Minimum Elements (July 2021), CycloneDX v1.4 Specification*
