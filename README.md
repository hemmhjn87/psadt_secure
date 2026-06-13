# 🛡 HemSpect v3.0

**Package Security Scanner**

> Compliance: NIST SP 800-53 Rev5 | CMMC 2.0 | IEC 62443-2-4 | CIS Controls v8 | MITRE ATT&CK

HemSpect is an enterprise security scanner purpose-built for organizations that deploy software using the **PowerShell App Deployment Toolkit (PSADT)**. It performs deep security analysis of deployment packages before they reach production endpoints — catching credential leaks, malware techniques, and compliance violations that antivirus and EDR solutions miss.

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| **HemSpect Engine** | 3-tier data leakage intelligence engine — extension classification, filename heuristics, and deep content regex scanning for connection strings, cloud tokens, XML credentials, and more |
| **60+ Detection Patterns** | AMSI bypasses, LOLBin abuse, WMI persistence, ETW tampering, credential dumping, obfuscation, and PSADT v4 cmdlet misuse |
| **Factory Scan Mode** | Batch-scan an entire package factory (300+ packages) in one command with a consolidated HTML dashboard |
| **Dynamic Secrets Detection** | Integrates Yelp's `detect-secrets` entropy engine for catching passwords that static regex misses |
| **MITRE ATT&CK Mapping** | Every finding is mapped to ATT&CK techniques with a visual heatmap in the HTML report |
| **Compliance Matrix** | Automatic compliance tagging against NIST 800-53, CMMC 2.0, IEC 62443, and CIS Controls v8 |
| **CVSS v3.1 Scoring** | Each finding includes a computed CVSS base score and vector string |
| **Cryptographic Signing** | ECDSA P-256 signed manifests for tamper-proof chain-of-custody |
| **3-Stage Approval Workflow** | `AUTO_SCAN` → `ANALYST_REVIEW` → `CISO_APPROVAL` with full audit trail |
| **SBOM Generation** | CycloneDX 1.4 JSON + SPDX 2.3 tag-value format with NVD CVE correlation |
| **Multi-Format Reports** | HTML dashboard, JSON, CSV, SARIF (GitHub/Azure DevOps), JUnit XML (CI/CD gating) |
| **MSI Custom Action Analysis** | Flags dangerous Type 1 (DLL), Type 2 (EXE), and Type 34/1074 (deferred system context) custom actions |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+

### Installation

```powershell
# Clone the repository
git clone https://github.com/hemmhjn87/psadt_secure.git
cd psadt_secure

# Create a virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Scan a Single Package

```powershell
# Interactive mode (prompts for report folder name)
python main.py scan "C:\Packages\MyApp" --format all

# Specify output directory
python main.py scan "C:\Packages\MyApp" -o "C:\HemSpect\MyApp" --format all --sign-report
```

### Factory Scan (Batch Mode)

```powershell
# Scan your entire package factory in one shot
python main.py factory-scan "\\server\PackageFactory" -o "C:\HemSpect\FactoryReport"
```

---

## 📖 Commands Reference

### `scan` — Scan a Single Package

```
python main.py scan <PACKAGE_PATH> [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-o`, `--output-dir` | Output directory for reports | `C:\HemSpect\<prompted>` |
| `-f`, `--format` | Output formats: `html,json,csv,sarif,junit,sbom,all` | `html,json,csv` |
| `--sign-report` | Generate ECDSA-signed manifest | off |
| `--signing-key` | Path to ECDSA private key PEM | ephemeral key |
| `--allowlist` | Path to `allowlist.yaml` for exception management | none |
| `--operator` | Operator name for audit log | system username |
| `--nvd-api-key` | NVD API key for SBOM CVE lookups | `NVD_API_KEY` env var |
| `--no-network` | Offline mode: skip NVD/OCSP lookups | off |
| `--ci` | CI/CD mode: JSON to stdout, minimal output | off |
| `--fail-on` | Severities that cause non-zero exit | `critical,high` |
| `--compliance` | Filter by framework: `nist,cmmc,iec62443,cis,all` | `all` |

### `factory-scan` — Batch Scan Entire Package Factory

```
python main.py factory-scan <FACTORY_PATH> [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-o`, `--output-dir` | Output directory for consolidated reports | `C:\HemSpect\factory_scan_TIMESTAMP` |
| `--operator` | Operator name for audit log | system username |

**Auto-discovery**: The factory scanner automatically identifies PSADT packages by looking for folders containing:
- `Deploy-Application.ps1`
- `Invoke-AppDeployToolkit.ps1`
- `AppDeployToolkit` subdirectory
- Any `.msi` or `.msix` files
- Any `.ps1` scripts

### `verify` — Verify Signed Manifest

```powershell
python main.py verify "C:\HemSpect\MyApp"
```

### `workflow` — Manage Approval Workflow

```powershell
# Analyst review
python main.py workflow analyst-review "C:\HemSpect\MyApp" "Jane.Smith" --approve --notes "All FPs validated"

# CISO approval
python main.py workflow ciso-approve "C:\HemSpect\MyApp" "CEO.Name" "AUTH-20260601" --approve
```

---

## 🔍 Scan Pipeline (9 Steps)

| Step | Engine | What It Does |
|------|--------|-------------|
| 1 | **PowerShell Analysis** | 60+ pattern matching against AMSI bypasses, LOLBins, persistence, credential dumping, PSADT cmdlet misuse |
| 2 | **Binary Analysis** | PE file inspection, Authenticode chain-of-trust verification, entropy analysis |
| 3 | **Credential Detection** | Static regex + Yelp `detect-secrets` entropy engine for passwords, API keys, tokens |
| 4 | **HemSpect Engine** | 3-tier data leakage sweep — dangerous file types, suspicious filenames, deep content regex |
| 5 | **Malware Patterns** | C2 indicators, process injection, ransomware keywords, data exfiltration |
| 6 | **Configuration Analysis** | Dependency scanning, config file analysis |
| 7 | **PSADT v4 Compliance** | Deprecated v3 API detection, cmdlet misuse, exit code handling |
| 8 | **MSI Analysis** | Custom action type classification, unsigned MSI detection |
| 9 | **Risk Scoring** | CVSS v3.1 computation, MITRE mapping, approval decision |

---

## 🕵 HemSpect — Data Leakage Intelligence Engine

HemSpect is our proprietary 3-tier data leakage detection engine that ensures no sensitive data ships inside deployment packages.

### Tier 1 — Extension Classifier
Instantly flags file types that should **never** exist in a deployment package:

| Category | Extensions |
|----------|-----------|
| Credential Stores | `.kdbx`, `.kdb`, `.keychain`, `.jks`, `.keystore`, `.pfx`, `.p12`, `.pem`, `.key`, `.ppk` |
| Email/Mailbox | `.ost`, `.pst`, `.eml`, `.msg` |
| Database Files | `.mdf`, `.ldf`, `.sdf`, `.sqlite`, `.bak` |
| RDP/VPN Configs | `.rdp`, `.rdg`, `.ovpn`, `.pcf` |
| Memory Dumps | `.dmp`, `.vmem`, `.vmdk` |

### Tier 2 — Filename Heuristic
Flags files with suspicious names like `password.txt`, `id_rsa`, `unattend.xml`, `web.config`, `.env`, `ntds.dit`, `kubeconfig`, and 13+ patterns.

### Tier 3 — Deep Content Regex
Scans file contents for:
- SQL/OLEDB/JDBC/MongoDB connection strings with embedded passwords
- XML credential elements and attributes
- .NET machine keys and validation keys
- Windows Unattend/Sysprep embedded passwords
- AWS/Azure/GCP cloud provider secrets
- OAuth Bearer/JWT tokens
- SMTP credentials
- Docker registry auth tokens
- WiFi passwords in exported profiles
- Registry exports with stored credentials

---

## 📊 Output Formats

| Format | File | Use Case |
|--------|------|----------|
| **HTML** | `report.html` | Interactive dashboard for analysts and auditors |
| **JSON** | `findings.json` | Programmatic consumption, SIEM integration |
| **CSV** | `findings.csv` | Excel/spreadsheet analysis |
| **SARIF** | `findings.sarif.json` | GitHub Advanced Security, Azure DevOps |
| **JUnit** | `findings_junit.xml` | CI/CD pipeline gating (Jenkins, GitLab, Azure Pipelines) |
| **CycloneDX** | `sbom.cyclonedx.json` | Software Bill of Materials (NTIA compliant) |
| **SPDX** | `sbom.spdx` | Alternative SBOM format |
| **Factory HTML** | `factory_report.html` | Consolidated dashboard for batch scans |
| **Factory CSV** | `factory_results.csv` | Batch scan results for Excel |
| **Factory JSON** | `factory_results.json` | Batch scan results for automation |

---

## 🔐 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | **APPROVED** — Package meets all security thresholds |
| `1` | **REVIEW REQUIRED** — Manual analyst review needed |
| `2` | **REJECTED** — Critical/High findings above threshold |
| `3` | **SCAN ERROR** — Exception during scan |
| `4` | **MANIFEST INVALID** — Signature verification failed |

---

## 📁 Project Structure

```
hemspect/
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies
├── config/
│   ├── rules.yaml                   # Custom detection rules
│   └── allowlist.yaml               # Exception management
├── src/
│   └── scanners/
│       ├── scan_psadt.py            # Core scanner engine + HemSpect
│       ├── report_generator.py      # Enterprise HTML report generator
│       ├── sbom_generator.py        # CycloneDX + SPDX SBOM generator
│       └── approval_workflow.py     # 3-stage approval workflow

```

---

## ⚙️ Configuration

### Custom Rules (`config/rules.yaml`)

Add custom detection patterns without modifying source code:

```yaml
custom_rules:
  my_company_api_key:
    pattern: "(?i)MYCOMPANY-API-[A-Za-z0-9]{32}"
    severity: CRITICAL
    description: "MyCompany API key detected"
    remediation: "Use Azure Key Vault instead"
```

### Allowlist (`config/allowlist.yaml`)

Suppress known false positives with audit trail:

```yaml
exceptions:
  - rule_id: hardcoded_credential
    file_pattern: "*/test_data/*"
    reason: "Test fixture data, not real credentials"
    approved_by: "Jane.Smith"
    expires: "2027-01-01"
```

---

## 🏭 Enterprise Deployment

### Scheduled Factory Scan (Windows Task Scheduler)

```powershell
# Create a nightly scheduled task
$action = New-ScheduledTaskAction -Execute "python" -Argument "main.py factory-scan \\server\PackageFactory -o C:\HemSpect\Nightly"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
Register-ScheduledTask -TaskName "HemSpect-Nightly" -Action $action -Trigger $trigger
```

### CI/CD Integration (Azure DevOps)

```yaml
- task: PythonScript@0
  inputs:
    scriptPath: 'main.py'
    arguments: 'scan $(Build.SourcesDirectory) --ci --fail-on critical,high --format sarif'
  displayName: 'PSADT Security Scan'
```

---

## 📜 Compliance Mapping

| Framework | Coverage |
|-----------|----------|
| **NIST SP 800-53 Rev5** | SI-3, SI-7, CM-7, AC-6, AU-9, SA-11 |
| **CMMC 2.0** | SI.1.210, SI.2.214, AU.2.041, CM.2.061 |
| **IEC 62443-2-4** | SR 3.2, SR 3.4 |
| **CIS Controls v8** | CIS-2, CIS-7, CIS-10, CIS-13 |
| **MITRE ATT&CK** | 30+ techniques across 14 tactics |

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -m 'feat: add new detection pattern'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Open a Pull Request

---

<p align="center">
  <sub>// Designed by <b>Hem</b></sub>
</p>
