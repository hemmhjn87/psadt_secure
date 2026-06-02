# HemSpect v3.0 — Operator Guide

> **Document**: Operator Procedures Manual  
> **Version**: 3.0.0  
> **Classification**: INTERNAL — SOC / Packaging Operations  
> **Last Updated**: 2026-06-01

---

## 1. Quick Start

```powershell
# Activate virtual environment
.venv\Scripts\Activate.ps1

# Basic scan (auto-detect format)
python main.py scan "C:\SCCM\Packages\MyApp_1.0"

# Full aerospace-grade scan with all outputs
python main.py scan "C:\SCCM\Packages\MyApp_1.0" `
    --format all `
    --compliance all `
    --operator "J.Smith" `
    --sign-report `
    --output-dir "C:\SecurityReports\MyApp_1.0_scan"

# CI/CD pipeline mode (returns exit code for pipeline gate)
python main.py scan "C:\SCCM\Packages\MyApp_1.0" --ci --format sarif,junit
```

---

## 2. Installation

### Prerequisites
- Python 3.10+ (3.11 recommended)
- Windows 10/11 or Windows Server 2019+
- PowerShell 5.1+ (for Authenticode signature checking)
- Network access to `services.nvd.nist.gov` (optional; graceful offline fallback)

### Setup Steps

```powershell
# 1. Clone or extract the HemSpect package
cd D:\Tools\hemspect

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python main.py --version
# Expected: HemSpect v3.0.0

# 5. Optional: Set environment variables
$env:PSADT_SCAN_OPERATOR = "YourName"    # Audit log operator ID
$env:NVD_API_KEY = "your-nvd-api-key"   # Get free key at nvd.nist.gov
$env:PSADT_SIGNING_KEY_PATH = "C:\Keys\psadt_signing.pem"  # ECDSA private key
```

### NVD API Key (Recommended)
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Register with your work email
3. Add key to environment: `$env:NVD_API_KEY = "your-key-here"`
- Without key: 5 requests/30s (slow, may throttle)
- With key: 50 requests/30s (standard org usage)

---

## 3. Scan Workflow

### Standard Scanning Procedure

```
┌──────────────────────────────────────────────────────────┐
│              PSADT Package Scanning Procedure             │
├──────────────────────────────────────────────────────────┤
│  1. RECEIVE package from Packaging Team                   │
│  2. RUN scan: python main.py scan <path> --operator <id> │
│  3. REVIEW HTML report in browser                         │
│  4. TRIAGE findings (TP/FP/Accepted Risk)                 │
│  5. ESCALATE if CRITICAL or HIGH remain after triage      │
│  6. SUBMIT to CAB with report hash + workflow state       │
│  7. ARCHIVE outputs per retention policy                  │
└──────────────────────────────────────────────────────────┘
```

### Step-by-Step

**Step 1: Run the Scan**
```powershell
python main.py scan "C:\Packages\AdobeReader_24.0" `
    --operator "SOC-Analyst-01" `
    --format html,json,sarif,sbom `
    --sign-report `
    --output-dir "C:\SecurityReports\AdobeReader_24.0"
```

**Step 2: Review the HTML Report**
```powershell
Start-Process "C:\SecurityReports\AdobeReader_24.0\report.html"
```

Report sections:
- **Executive Summary**: Traffic-light status, risk score gauge
- **Compliance Matrix**: Which NIST/CMMC/CIS controls are failing
- **Findings Explorer**: All issues sorted by severity, filterable
- **MITRE ATT&CK Heatmap**: Visual technique mapping
- **SBOM Inventory**: Component list with CVE status
- **Audit Trail**: Chain-of-custody

**Step 3: Analyst Review (if REVIEW_REQUIRED)**
```powershell
# After reviewing findings, record analyst disposition
python main.py workflow analyst-review `
    "C:\SecurityReports\AdobeReader_24.0" `
    --analyst "J.Smith" `
    --approve `
    --notes "Reviewed 3 findings: 2 confirmed FP (registry change is expected for PDF viewer), 1 HIGH accepted risk with network controls in place. CHG-2026-0456 approved."
```

**Step 4: CISO Approval (if required by policy)**
```powershell
python main.py workflow ciso-approve `
    "C:\SecurityReports\AdobeReader_24.0" `
    --ciso "CISO-Name" `
    --authorization "AUTH-2026-0123" `
    --approve `
    --notes "Approved for deployment to managed endpoints only. Exclude OT network."
```

**Step 5: Verify Report Integrity**
```powershell
# Verify the cryptographic manifest before CAB submission
python main.py verify "C:\SecurityReports\AdobeReader_24.0"
# Output: ✅ Manifest signature VALID — Report has not been tampered
```

---

## 4. Understanding Scan Results

### Approval Status

| Status | Meaning | Action Required |
|--------|---------|----------------|
| ✅ **APPROVED** | 0 critical, 0 high, risk score < 30 | Submit to CAB immediately |
| ⚠️ **REVIEW_REQUIRED** | High findings OR medium risk score | Analyst review → CAB |
| ❌ **REJECTED** | Critical finding(s) OR risk > 75 | Packaging team must remediate |

### Risk Score Interpretation

| Score | Grade | Action |
|-------|-------|--------|
| 0–20 | 🟢 CLEAN | APPROVED |
| 21–50 | 🟡 LOW RISK | REVIEW (analyst triage) |
| 51–75 | 🟠 MEDIUM RISK | REVIEW (senior analyst + CISO notification) |
| 76–100 | 🔴 HIGH RISK | REJECTED (mandatory remediation) |

### Severity Definitions

| Severity | CVSS Range | SLA (Remediation) | Deployment Block |
|----------|-----------|-------------------|-----------------|
| CRITICAL | 9.0–10.0 | 24 hours | ✅ YES — Auto-REJECTED |
| HIGH | 7.0–8.9 | 5 business days | ✅ YES — Analyst approval needed |
| MEDIUM | 4.0–6.9 | 30 days | ⚠️ Review required |
| LOW | 0.1–3.9 | Best effort | ℹ️ Informational |

---

## 5. Common Findings and Remediation

### CRITICAL: `hardcoded_credential` (CWE-798)
**What it means**: A password, API key, or secret is hardcoded in the script.  
**Fix**:
```powershell
# ❌ BAD
$password = "MySecret123"

# ✅ GOOD — Use SCCM Task Sequence Variable (marked Private)
$password = $TSEnv.Value("_SMSTSMyAppPassword")

# ✅ GOOD — Use Windows Credential Manager
$cred = Get-StoredCredential -Target "MyAppServiceAccount"
```

### CRITICAL: `invoke_expression` (CWE-95)
**What it means**: Dynamic code execution — any string can become executable code.  
**Fix**:
```powershell
# ❌ BAD
Invoke-Expression $userInputOrDynamicString

# ✅ GOOD — Use explicit function calls
& $scriptPath -Parameter $value

# ✅ GOOD — If ScriptBlock is needed, validate it
$validated = [scriptblock]::Create($knownSafeString)
```

### CRITICAL: `amsi_patch_memory` (T1562.001)
**What it means**: The script attempts to disable Windows AMSI (Antimalware Scan Interface).  
**Fix**: Remove entirely. There is NO legitimate reason for a deployment package to disable AMSI. If vendor installer requires it, escalate to vendor and reject package until fixed.

### HIGH: `external_download` (CWE-95)
**What it means**: The script downloads content from the internet at runtime.  
**Fix**:
```powershell
# ❌ BAD
(New-Object System.Net.WebClient).DownloadFile($url, $dest)

# ✅ GOOD — Bundle content in package SupportFiles
Copy-ADTFile -Source "$dirSupportFiles\component.msi" -Destination $dest

# ✅ IF download required — Use internal server, validate hash
$url = "https://internal.company.com/trusted/file.msi"
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
$expectedHash = "ABC123..."
if ((Get-FileHash $dest -Algorithm SHA256).Hash -ne $expectedHash) {
    throw "Hash mismatch — file integrity check failed"
}
```

### HIGH: `unsigned_binary`
**What it means**: An executable or DLL in SupportFiles is not Authenticode-signed.  
**Fix**: Request the vendor to provide a properly signed binary. If not possible, obtain internal signing:
```powershell
# Sign with company certificate (requires code signing cert)
Set-AuthenticodeSignature -FilePath ".\Setup.exe" `
    -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
```

### MEDIUM: `registry_manipulation`
**What it means**: The script modifies HKLM registry keys.  
**Evaluation**: This is often legitimate for application configuration. Add a comment explaining the business justification, or add to allowlist with ticket reference.

---

## 6. Allowlist Management

When a finding is a known false positive or has an accepted business justification:

```powershell
# Edit config/allowlist.yaml and add an exception:
# - id: exc-001
#   rule_id: registry_manipulation
#   file_pattern: "Deploy-Application.ps1"
#   approved_by: "CISO-Name"
#   approved_date: "2026-06-01"
#   ticket: "CHG-2026-0456"
#   expiry: "2026-12-31"
#   justification: "HKLM registry change required for application license key."
#   risk_accepted: "LOW - controlled key path, documented in architecture."
```

**Allowlist Policy Rules:**
1. Every exception MUST have a ticket number
2. Every exception MUST have an expiry date (max 365 days)
3. The following patterns can NEVER be allowlisted: `credential_dumping`, `amsi_patch_memory`, `amsi_reflection`, `data_exfiltration`, all `c2_*` patterns
4. Allowlist changes require second-pair-of-eyes review by senior SOC analyst

---

## 7. CI/CD Integration

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
- task: PythonScript@0
  displayName: 'PSADT Security Scan'
  inputs:
    scriptSource: 'filePath'
    scriptPath: '$(Build.SourcesDirectory)/tools/hemspect/main.py'
    arguments: >
      scan "$(PACKAGE_PATH)"
      --ci
      --format sarif,junit
      --operator "$(Build.RequestedFor)"
      --fail-on critical,high
  env:
    NVD_API_KEY: $(NVD_API_KEY)

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '$(SCAN_OUTPUT)/findings_junit.xml'
    testRunTitle: 'PSADT Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(SCAN_OUTPUT)/findings.sarif'
    artifactName: 'CodeAnalysisLogs'
```

### GitHub Actions

```yaml
- name: PSADT Security Scan
  run: |
    python main.py scan "${{ env.PACKAGE_PATH }}" \
      --ci \
      --format sarif,junit \
      --operator "${{ github.actor }}" \
      --fail-on critical,high
  env:
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
  if: always()
```

### Exit Code Reference

| Code | Meaning | Pipeline Action |
|------|---------|----------------|
| 0 | APPROVED | ✅ Continue deployment |
| 1 | REVIEW REQUIRED | ⚠️ Pause — manual review |
| 2 | REJECTED | ❌ Fail build — notify team |
| 3 | SCAN ERROR | ❌ Fail build — investigate |
| 4 | MANIFEST INVALID | ❌ Fail build — report tampered |

---

## 8. Report Artifacts Reference

After a scan, the output directory contains:

| File | Format | Purpose |
|------|--------|---------|
| `report.html` | HTML | Executive dashboard — open in browser |
| `findings.json` | JSON | Machine-readable findings data |
| `findings.csv` | CSV | Import to Excel/Jira/ServiceNow |
| `findings.sarif` | SARIF 2.1 | IDE/pipeline integration |
| `findings_junit.xml` | JUnit XML | CI/CD test results |
| `sbom.cyclonedx.json` | CycloneDX 1.4 | Software Bill of Materials |
| `sbom.spdx` | SPDX 2.3 | Alternative SBOM format |
| `manifest.json` | JSON | Cryptographic report manifest |
| `manifest.sig` | Base64 DER | ECDSA P-256 signature |
| `manifest_public.pem` | PEM | Public key for verification |
| `audit.log` | JSONL | Tamper-evident audit log |
| `workflow_state.json` | JSON | Approval workflow state |
| `nvd_cache.db` | SQLite | NVD CVE cache |

---

## 9. Escalation Path

```
Package Flagged as REJECTED
         │
         ▼
   SOC Analyst Review
   (Triage findings, mark FP)
         │
         ├── All findings are FP ──► Re-run with allowlist ──► APPROVED
         │
         ├── HIGH findings with ──► CISO Notification ──► Risk Acceptance
         │   accepted risk           (AUTH number required)     │
         │                                                      ▼
         │                                              Conditional Deploy
         │                                              (document risk)
         │
         └── CRITICAL findings ──► Packaging Team ──► Remediate ──► Re-scan
             (non-negotiable)      (48hr SLA)
```

### Escalation Contacts
Configure in your organization's runbook. Typical chain:
1. **L1 SOC Analyst** — Initial triage, FP marking
2. **L2 Senior Analyst** — High-risk acceptance decisions
3. **CISO / Security Manager** — Critical/CISO approval, exception authorization
4. **CERT/Incident Response** — If active malware indicators found

---

## 10. Troubleshooting

### "pefile not found"
```powershell
pip install pefile==2023.2.7
```

### "cryptography not found"
```powershell
pip install cryptography>=42.0.0
```

### NVD lookups timing out
```powershell
# Use offline mode
python main.py scan <path> --no-network
# Or set API key for higher rate limit
$env:NVD_API_KEY = "your-key"
```

### False positive — registry change is expected
Add to `config/allowlist.yaml` with justification and ticket number (see Section 6).

### Scan fails on large packages (>10GB)
```powershell
# The scanner processes files sequentially; large packages may take time
# Monitor progress in console output
# Use --severity-threshold HIGH to skip LOW/MEDIUM patterns for speed
python main.py scan <path> --severity-threshold HIGH
```

---

*Operator Guide maintained by: Security Operations*  
*Questions: Contact your SOC team lead*  
*HemSpect Issues: Review project README.md*
