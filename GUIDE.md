# HemSpect v3.0 — User Guide

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Scanning Your First Package](#2-scanning-your-first-package)
3. [Understanding the Report](#3-understanding-the-report)
4. [Factory Scan Mode](#4-factory-scan-mode)
5. [Managing False Positives](#5-managing-false-positives)
6. [Approval Workflow](#6-approval-workflow)
7. [Verifying Report Integrity](#7-verifying-report-integrity)
8. [Responding to a Pentest / Audit](#8-responding-to-a-pentest--audit)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Getting Started

### Installation

```powershell
git clone https://github.com/hemmhjn87/psadt_secure.git
cd psadt_secure
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Verify Installation

```powershell
python main.py scan --help
```

You should see the full list of scan options.

---

## 2. Scanning Your First Package

### Interactive Mode (Recommended for first use)

```powershell
python main.py scan "C:\Packages\GoogleChrome" --format all
```

The scanner will:
1. Ask you for a report folder name (e.g., `ChromeReport`)
2. Save all reports to `C:\HemSpect\ChromeReport\`
3. Run all 9 scan steps including HemSpect
4. Generate HTML, JSON, CSV, SARIF, JUnit, and SBOM reports

### CI/CD Mode (No prompts)

```powershell
python main.py scan "C:\Packages\GoogleChrome" -o "C:\Reports\Chrome" --ci --format all
```

### What the Scanner Checks

The scanner runs 9 steps in sequence:

```
[Step 1/9] PowerShell Analysis        — 60+ security patterns
[Step 2/9] Binary Analysis             — PE inspection, Authenticode
[Step 3/9] Credential Detection        — Regex + detect-secrets entropy
[Step 4/9] HemSpect Data Leakage      — Extension/filename/content analysis
[Step 5/9] Malware Patterns            — C2, injection, ransomware
[Step 6/9] Configuration Analysis      — Config files, dependencies
[Step 7/9] PSADT v4 Compliance         — Deprecated APIs, cmdlet misuse
[Step 8/9] MSI Analysis                — Custom actions, signatures
[Step 9/9] Risk Scoring                — CVSS, MITRE mapping, approval
```

---

## 3. Understanding the Report

After scanning, open `report.html` in your browser. The report has these sections:

### Executive Summary
Shows total findings by severity (Critical/High/Medium/Low) and overall risk score (0-100).

### Risk Assessment
Visual gauge showing the risk score with severity breakdown bars.

### Compliance Matrix
Shows which NIST, CMMC, IEC, and CIS controls are affected by the findings.

### Findings Explorer
Interactive table of all findings. Click any row to expand and see:
- **File & Line Number**: Exact location of the issue
- **MITRE ATT&CK Technique**: What attack this enables
- **CVSS Score**: Severity rating
- **Remediation**: Step-by-step fix instructions
- **Compliance Tags**: Which frameworks are affected

### MITRE ATT&CK Heatmap
Visual heatmap showing which ATT&CK tactics and techniques are covered by the findings.

### Approval Status
- **APPROVED** (green): 0 critical, 0 high, risk score < 30
- **REVIEW REQUIRED** (orange): Has high findings or risk 30-75
- **REJECTED** (red): Has critical findings or risk > 75

---

## 4. Factory Scan Mode

Use this when you need to scan your entire package factory at once (e.g., after a pentest).

### Running a Factory Scan

```powershell
python main.py factory-scan "\\server\PackageFactory" -o "C:\HemSpect\FullAudit"
```

### What It Does

1. **Auto-discovers** all packages (folders with `.ps1`, `.msi`, or `AppDeployToolkit`)
2. **Scans each package** with the full 9-step engine
3. **Generates per-package reports** in subdirectories
4. **Creates a consolidated dashboard** (`factory_report.html`) showing all packages ranked by risk

### Factory Report

Open `factory_report.html` to see:
- Total packages scanned
- How many were Rejected / Review Required / Approved
- A table sorted by risk score (worst packages at top)
- Click "Open" on any row to jump to that package's detailed report

### Scheduling Nightly Scans

```powershell
# Windows Task Scheduler
$action = New-ScheduledTaskAction -Execute "python" `
  -Argument "main.py factory-scan \\server\Packages -o C:\HemSpect\Nightly" `
  -WorkingDirectory "D:\project\hemspect"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
Register-ScheduledTask -TaskName "HemSpect-Nightly" -Action $action -Trigger $trigger
```

---

## 5. Managing False Positives

### Using the Allowlist

Create or edit `config\allowlist.yaml`:

```yaml
exceptions:
  # Example: suppress a known false positive
  - rule_id: hardcoded_credential
    file_pattern: "*/TestData/*"
    reason: "Test fixture data with dummy credentials"
    approved_by: "Jane.Smith"
    expires: "2027-01-01"

  # Example: suppress HemSpect extension detection for a legitimate .bak file
  - rule_id: hemspect_ext_bak
    file_pattern: "*/Backup/config.bak"
    reason: "Legitimate config backup, no credentials"
    approved_by: "John.Doe"
    expires: "2026-12-31"
```

### Using the Allowlist in Scans

```powershell
python main.py scan "C:\Packages\MyApp" --allowlist config\allowlist.yaml --format all
```

Suppressed findings are still recorded in the report under "Suppressed Findings" for audit transparency.

---

## 6. Approval Workflow

HemSpect implements a 3-stage approval workflow:

```
AUTO_SCAN → ANALYST_REVIEW → CISO_APPROVAL
```

### Stage 1: Auto Scan (Automatic)
When you run a scan, the scanner automatically determines if the package passes or fails.

### Stage 2: Analyst Review

```powershell
# Analyst approves (marks findings as false positives / accepted risk)
python main.py workflow analyst-review "C:\HemSpect\MyApp" "Jane.Smith" --approve --notes "All findings verified as FP"

# Analyst rejects (confirms findings are true positives)
python main.py workflow analyst-review "C:\HemSpect\MyApp" "Jane.Smith" --reject --notes "Real credentials found"
```

### Stage 3: CISO Approval

```powershell
# CISO approves deployment
python main.py workflow ciso-approve "C:\HemSpect\MyApp" "CEO.Name" "AUTH-20260601" --approve

# CISO rejects deployment
python main.py workflow ciso-approve "C:\HemSpect\MyApp" "CEO.Name" "AUTH-20260601" --reject
```

---

## 7. Verifying Report Integrity

If you used `--sign-report`, the scanner generates an ECDSA-signed manifest. Anyone can verify it:

```powershell
python main.py verify "C:\HemSpect\MyApp"
```

This confirms:
- The report files haven't been tampered with since the scan
- All file hashes match the signed manifest
- The cryptographic signature is valid

---

## 8. Responding to a Pentest / Audit

If a pentester used **Snaffler** (or similar) against your package factory and found issues, here's your response plan:

### Step 1: Run a Full Factory Scan

```powershell
python main.py factory-scan "\\server\PackageFactory" -o "C:\HemSpect\AuditResponse" --operator "YourName"
```

### Step 2: Review the Dashboard

Open `C:\HemSpect\AuditResponse\factory_report.html` and identify the worst packages.

### Step 3: Fix the Top Offenders

For each rejected package:
1. Open the individual `report.html`
2. Follow the remediation steps in the Findings Explorer
3. Re-scan to confirm the fix

### Step 4: Document Exceptions

For legitimate false positives, add them to `config\allowlist.yaml` with proper justification.

### Step 5: Present to Auditors

Hand the auditors:
- `factory_report.html` — Consolidated dashboard showing all 300+ packages
- `factory_results.csv` — Machine-readable results for their compliance tools
- `factory_results.json` — Full structured data
- Individual signed manifests proving report integrity

### What Makes This Better Than Snaffler

| Snaffler | HemSpect |
|----------|-------------|
| Finds the problem | Finds + maps to MITRE/NIST/CMMC |
| Raw text output | Interactive HTML dashboard |
| No remediation guidance | Step-by-step fix instructions |
| No compliance mapping | Full compliance matrix |
| No approval workflow | 3-stage workflow with audit trail |
| No cryptographic proof | ECDSA-signed manifests |

---

## 9. Troubleshooting

### "No PowerShell scripts found"
The package directory doesn't contain `.ps1` files. This is normal for packages that only contain `.msi` installers.

### Unicode encoding errors
HemSpect automatically forces UTF-8 encoding. If you still see issues, set the environment variable:
```powershell
$env:PYTHONIOENCODING = "utf-8"
```

### "detect-secrets scan failed"
This is non-fatal. The scanner falls back to static regex patterns. To fix, ensure `detect-secrets` is installed:
```powershell
pip install detect-secrets==1.4.0
```

### Factory scan finds 0 packages
Ensure your factory root directory contains **subdirectories** (one per package). The scanner looks for folders containing `.ps1`, `.msi`, or `AppDeployToolkit`.

### Slow scans on large packages
HemSpect skips files larger than 5MB for performance. If you have very large packages, the MSI analysis step may take time due to PowerShell subprocess calls.

---

<p align="center">
  <sub>// Designed by <b>Hem</b></sub>
</p>
