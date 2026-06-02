# 🧪 HemSpect Testing Guide

Complete guide for running, testing, and integrating HemSpect security scanner.

---

## 📋 Table of Contents

1. [Installation](#installation)
2. [Running Scans](#running-scans)
3. [Understanding Output](#understanding-output)
4. [Exit Codes](#exit-codes)
5. [Test Cases](#test-cases)
6. [5-Minute Quick Test](#5-minute-quick-test)
7. [Detection Coverage](#detection-coverage)
8. [Troubleshooting](#troubleshooting)
9. [CI/CD Integration](#cicd-integration)

---

## 🔧 Installation

### Prerequisites
- Python 3.8+
- Windows OS (for full PE binary analysis)
- Administrator access (for event log scanning)

### Step 1: Navigate to Project
```bash
cd d:\project\hemspect
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

**Expected Output**:
```
Successfully installed pefile-2023.2.7 detect-secrets-1.4.0 yara-python-4.3.2 semgrep-1.45.0 ...
```

**Installation Details**:
- **Time**: 2-5 minutes
- **Disk Space**: ~200 MB
- **Libraries**: 12 packages (see requirements.txt)

### Step 3: Verify Installation
```bash
python main.py
```

**Expected Output**:
```
HemSpect: PSADT v4 Security Scanner

Usage:
  python main.py <package_path> [output_dir]

Example:
  python main.py C:\SCCM\Packages\MyApp
  python main.py C:\SCCM\Packages\MyApp C:\Reports
```

---

## 🚀 Running Scans

### Basic Usage: Single Package
```bash
python main.py "C:\SCCM\Packages\MyApp"
```

**What Happens**:
1. Scanner discovers package structure
2. Scans all .ps1 PowerShell scripts
3. Analyzes .exe/.dll binaries
4. Checks for embedded credentials
5. Tests for malware patterns
6. Generates report (2-10 minutes)

### Advanced Usage: Custom Output Directory
```bash
python main.py "C:\SCCM\Packages\MyApp" "C:\Reports"
```

**Output** (`C:\Reports\psadt_scan_YYYYMMDD_HHMMSS/`):
- `report.html` - Visual dashboard
- `findings.json` - Machine-readable data
- Console summary

### Batch Scanning: Multiple Packages
```bash
for /D %pkg in (C:\SCCM\Packages\*) do (
    python main.py "%pkg" "C:\Reports"
)
```

**Example with Echo**:
```bash
for /D %pkg in (C:\SCCM\Packages\*) do (
    echo Scanning %pkg%
    python main.py "%pkg" "C:\Reports"
    if errorlevel 1 (
        echo ❌ REJECTED: %pkg%
    ) else (
        echo ✅ APPROVED: %pkg%
    )
)
```

---

## 📊 Understanding Output

### Output Directory Structure
```
psadt_scan_20260601_120000/
├─ report.html              (Visual dashboard - open in browser)
├─ findings.json            (Structured data - machine readable)
└─ console output           (Real-time scanning feedback)
```

### report.html Dashboard
**Sections**:
- 📊 Summary statistics (total issues, severity breakdown)
- 🔴 Critical findings (must fix)
- 🟠 High findings (should fix)
- 🟡 Medium findings (nice to fix)
- 💡 Remediation guidance
- 🎯 Overall approval status

**View**:
```bash
# Windows
start psadt_scan_*\report.html

# Or manually open in any browser
```

### findings.json Structure
```json
{
  "timestamp": "2026-06-01T12:00:00Z",
  "package": "MyApp",
  "package_path": "C:\\SCCM\\Packages\\MyApp",
  "summary": {
    "total_issues": 3,
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0,
    "approval_status": "REJECTED"
  },
  "issues": [
    {
      "type": "hardcoded_credential",
      "severity": "CRITICAL",
      "file": "Deploy-Application.ps1",
      "line": 45,
      "pattern": "$password = \"secret123\"",
      "remediation": "Use TS Variable instead"
    }
  ]
}
```

**Parse with PowerShell**:
```powershell
$findings = Get-Content "psadt_scan_*/findings.json" | ConvertFrom-Json
$findings.summary
```

---

## 🎯 Exit Codes

### For CI/CD Integration

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| **0** | ✅ APPROVED | Package is safe, proceed with deployment |
| **1** | ❌ REJECTED | Package has issues, fix before deployment |

### Usage Examples

**Conditional Deployment**:
```bash
python main.py "package_path"
if %errorlevel% equ 0 (
    echo ✅ APPROVED - Deploying to SCCM
    # Deploy to SCCM here
) else (
    echo ❌ REJECTED - Fix security issues
    # Block deployment
)
```

**GitHub Actions**:
```yaml
- name: Scan PSADT Package
  run: python main.py "package_path"
```

**Azure DevOps**:
```yaml
- script: python main.py "package_path"
  failOnStderr: true
```

---

## 🧪 Test Cases

### Test 1: Safe Package ✅

**Create Test Package**:
```powershell
mkdir C:\Test\SafeApp
@'
Write-Host "Installing SafeApp v1.0"
$appName = "MyApp"
$version = "1.0"
[System.Environment]::SetEnvironmentVariable("AppName", $appName)
'@ | Out-File C:\Test\SafeApp\Deploy-Application.ps1
```

**Run Scan**:
```bash
python main.py "C:\Test\SafeApp"
```

**Expected Result**:
```
✅ PACKAGE APPROVED FOR DEPLOYMENT
Issues Found: 0
Exit Code: 0
```

---

### Test 2: Hardcoded Password ❌

**Create Test Package**:
```powershell
mkdir C:\Test\CredApp
@'
$dbPassword = "MySecurePassword123"
$sqlConnStr = "Server=db.company.com;Password=$dbPassword"
Write-Host "Connecting to database..."
'@ | Out-File C:\Test\CredApp\Deploy-Application.ps1
```

**Run Scan**:
```bash
python main.py "C:\Test\CredApp"
```

**Expected Result**:
```
❌ PACKAGE REJECTED - SECURITY ISSUES FOUND

CRITICAL Issues: 1
  • Hardcoded credential detected
    Line 1: $dbPassword = "MySecurePassword123"
    Severity: CRITICAL
    Fix: Use SCCM Task Sequence variable

Exit Code: 1
```

---

### Test 3: Multiple Vulnerabilities ❌

**Create Test Package**:
```powershell
mkdir C:\Test\VulnApp
@'
# Multiple issues
$password = "Admin123"
Clear-EventLog -LogName Application
Set-ItemProperty HKLM:\Software\Policies -Name "Disabled" -Value 1
Invoke-Expression $userInput
'@ | Out-File C:\Test\VulnApp\Deploy-Application.ps1
```

**Run Scan**:
```bash
python main.py "C:\Test\VulnApp"
```

**Expected Result**:
```
❌ PACKAGE REJECTED - SECURITY ISSUES FOUND

CRITICAL Issues: 2
  • Hardcoded credential
  • Invoke-Expression with variable

HIGH Issues: 1
  • Registry manipulation

CRITICAL Issues: 1
  • Event log clearing

Total: 4 Issues
Exit Code: 1
```

---

### Test 4: UAC Bypass ❌

**Create Test Package**:
```powershell
mkdir C:\Test\UACApp
@'
# Disable UAC
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 0 -Force
'@ | Out-File C:\Test\UACApp\Deploy-Application.ps1
```

**Run Scan**:
```bash
python main.py "C:\Test\UACApp"
```

**Expected Result**:
```
❌ PACKAGE REJECTED

CRITICAL Issues: 1
  • UAC bypass attempt detected
    Fix: Remove EnableLUA modification

Exit Code: 1
```

---

### Test 5: Lateral Movement ❌

**Create Test Package**:
```powershell
mkdir C:\Test\LateralApp
@'
# Lateral movement attempt
$computers = Get-ADComputer -Filter * | Select -ExpandProperty Name
foreach ($comp in $computers) {
    Invoke-Command -ComputerName $comp -ScriptBlock { Get-Process }
}
'@ | Out-File C:\Test\LateralApp\Deploy-Application.ps1
```

**Run Scan**:
```bash
python main.py "C:\Test\LateralApp"
```

**Expected Result**:
```
❌ PACKAGE REJECTED

HIGH Issues: 1
  • Lateral movement capability detected
    Pattern: Invoke-Command -ComputerName
    Fix: Restrict to local system only

Exit Code: 1
```

---

## ⏱️ 5-Minute Quick Test

Complete testing in 5 minutes:

```powershell
# 1️⃣ Install (2 min)
cd d:\project\hemspect
pip install -r requirements.txt

# 2️⃣ Create vulnerable test package (1 min)
mkdir C:\Test\VulnerableApp
@'
$password = "secret123"
Clear-EventLog -LogName Application
'@ | Out-File C:\Test\VulnerableApp\Deploy-Application.ps1

# 3️⃣ Scan (1 min)
python main.py "C:\Test\VulnerableApp"

# 4️⃣ View report (1 min)
start psadt_scan_*\report.html
```

**Total Time**: 5 minutes ⏱️  
**Result**: See detailed HTML report with findings

---

## 🔍 Detection Coverage

### Critical Issues 🔴
Scanner detects:
- ✅ Hardcoded passwords (plaintext)
- ✅ SecureString with -AsPlainText flag
- ✅ Invoke-Expression with user input
- ✅ Clear-EventLog commands
- ✅ UAC bypass attempts (EnableLUA = 0)
- ✅ Base64 encoded credentials
- ✅ Connection strings with passwords
- ✅ API key patterns

### High Issues 🟠
- ✅ Unsigned binaries (.exe/.dll)
- ✅ Lateral movement (Invoke-Command -ComputerName)
- ✅ Service creation (New-Service)
- ✅ Registry manipulation (HKLM changes)
- ✅ External downloads (DownloadString)
- ✅ COM object creation (New-Object COM)
- ✅ DLL execution (rundll32, regsvr32)

### Medium Issues 🟡
- ✅ WMI queries
- ✅ File permission changes
- ✅ Network configuration
- ✅ Scheduled task creation

---

## 🔧 Troubleshooting

### Issue: "ModuleNotFoundError"
**Symptom**:
```
ModuleNotFoundError: No module named 'pefile'
```

**Solution**:
```bash
pip install -r requirements.txt --force-reinstall
```

---

### Issue: "Permission Denied"
**Symptom**:
```
PermissionError: [Errno 13] Permission denied
```

**Solution**:
```bash
# Run as Administrator
# Or use --user flag
python -m pip install --user -r requirements.txt
```

---

### Issue: Slow Scan (>15 minutes)
**Symptom**:
```
Scanning... please wait (takes 2-10 min)
```

**Reason**: 
- Large package with many binaries
- Semgrep deep analysis running
- First run downloads Semgrep rules

**Solution**:
- Be patient (normal behavior)
- Subsequent scans are faster
- Use smaller packages for testing

---

### Issue: "Package Path Not Found"
**Symptom**:
```
Error: Package path does not exist
```

**Solution**:
```bash
# Check path exists
dir "C:\SCCM\Packages\MyApp"

# Use absolute path
python main.py "C:\SCCM\Packages\MyApp"

# Not relative path
python main.py "..\Packages\MyApp"  # ❌ Wrong
```

---

### Issue: Unsigned Binary Warning
**Symptom**:
```
Warning: Unable to verify binary signature
```

**Reason**: Package contains unsigned .exe/.dll files  
**Action**: This is expected for many PSADT packages - sign them if possible

---

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
name: PSADT Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          cd hemspect
          pip install -r requirements.txt
      
      - name: Scan package
        run: |
          cd hemspect
          python main.py "${{ github.workspace }}\package"
        continue-on-error: false
```

---

### Azure DevOps
```yaml
trigger:
  - main

pool:
  vmImage: 'windows-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.10'

  - script: |
      cd hemspect
      pip install -r requirements.txt
    displayName: 'Install dependencies'

  - script: |
      cd hemspect
      python main.py "$(Build.SourcesDirectory)\package"
    displayName: 'Scan PSADT package'
    failOnStderr: true
```

---

### Jenkins
```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                bat '''
                    cd hemspect
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Scan') {
            steps {
                bat '''
                    cd hemspect
                    python main.py "%WORKSPACE%\\package"
                '''
            }
        }
    }
    
    post {
        always {
            publishHTML([
                reportDir: 'hemspect/psadt_scan_*',
                reportFiles: 'report.html',
                reportName: 'PSADT Security Report'
            ])
        }
    }
}
```

---

### SCCM Pre-Deployment Hook
```powershell
# Save as: C:\SCCM\PreDeploymentCheck.ps1

param(
    [Parameter(Mandatory=$true)]
    [string]$PackagePath
)

# Run security scan
$scanDir = "d:\project\hemspect"
Push-Location $scanDir

python main.py $PackagePath
$exitCode = $LASTEXITCODE

Pop-Location

if ($exitCode -eq 0) {
    Write-Host "✅ Package approved for deployment"
    exit 0
} else {
    Write-Host "❌ Package rejected - security issues found"
    Write-Host "See report in: psadt_scan_*\report.html"
    exit 1
}
```

---

### SCCM Integration Script
```powershell
# Call from SCCM deployment to gate packages

$packagePath = "C:\SCCM\Packages\MyApp"
$reportPath = "C:\SCCM\Reports"

# Scan package
& "C:\SCCM\PreDeploymentCheck.ps1" -PackagePath $packagePath

if ($LASTEXITCODE -ne 0) {
    # Package rejected - send notification
    Send-MailMessage -SmtpServer "smtp.company.com" `
        -From "sccm@company.com" `
        -To "security@company.com" `
        -Subject "Package Rejected: Security Issues" `
        -Body "Package $packagePath has security issues and was rejected."
    
    exit 1
}

# Package approved - proceed with deployment
Write-Host "Deploying to SCCM..."
```

---

## 📈 Testing Checklist

Complete all tests:

| # | Test | Command | Expected | Status |
|---|------|---------|----------|--------|
| 1 | Install | `pip install -r requirements.txt` | ✅ Complete | ☐ |
| 2 | Help | `python main.py` | ✅ Show usage | ☐ |
| 3 | Safe package | `python main.py C:\Test\SafeApp` | ✅ APPROVED (0) | ☐ |
| 4 | Credentials | `python main.py C:\Test\CredApp` | ❌ REJECTED (1) | ☐ |
| 5 | Multiple issues | `python main.py C:\Test\VulnApp` | ❌ REJECTED (1) | ☐ |
| 6 | UAC bypass | `python main.py C:\Test\UACApp` | ❌ REJECTED (1) | ☐ |
| 7 | Lateral move | `python main.py C:\Test\LateralApp` | ❌ REJECTED (1) | ☐ |
| 8 | Custom output | `python main.py C:\Test\App C:\Out` | ✅ Report in C:\Out | ☐ |
| 9 | Report HTML | Open `report.html` | ✅ Visual dashboard | ☐ |
| 10 | Report JSON | Parse `findings.json` | ✅ Valid JSON | ☐ |

---

## 📚 Additional Resources

- [OVERVIEW.md](OVERVIEW.md) - Project overview
- [README.md](README.md) - Full documentation
- [QUICK_START.md](QUICK_START.md) - 5-minute guide
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) - Architecture
- [COMPARISON_WITH_PPE_GUARD.md](COMPARISON_WITH_PPE_GUARD.md) - Tool comparison

---

## 🎓 Learning Path

1. **Read**: [OVERVIEW.md](OVERVIEW.md) (5 min)
2. **Install**: Follow [Installation](#installation) section (5 min)
3. **Test**: Run [5-Minute Quick Test](#5-minute-quick-test) (5 min)
4. **Review**: Read [Understanding Output](#understanding-output) (5 min)
5. **Integrate**: Choose CI/CD platform from [CI/CD Integration](#cicd-integration) (10 min)

**Total**: 30 minutes from zero to production

---

**Ready to test?** Start with the [5-Minute Quick Test](#5-minute-quick-test)! 🚀
