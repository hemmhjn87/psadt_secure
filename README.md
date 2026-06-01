# PSADT-Secure: README

**PSADT-Secure** is a dedicated security scanner for PSADT v4 (Powershell Application Deployment Toolkit) packages used in enterprise software deployment via SCCM.

## Purpose

Scan PSADT packages **BEFORE deployment** to detect:
- 🔴 Hardcoded credentials (passwords, API keys, certificates)
- 🔴 Privilege escalation attempts (UAC bypass, etc.)
- 🔴 Lateral movement capabilities (remote code execution)
- 🔴 Evidence destruction (event log clearing)
- 🔴 Code injection vulnerabilities
- 🔴 Unsigned or malicious binaries
- 🔴 Malware signatures

## Installation

```bash
# Clone/setup project
cd psadt-secure

# Install dependencies
pip install -r requirements.txt

# Verify installation
python src/scanners/scan_psadt.py --help
```

## Quick Start

### Scan a PSADT Package
```bash
python src/scanners/scan_psadt.py "C:\SCCM\Packages\MyPSADTPackage"
```

**Output**:
- `psadt_scan_[timestamp]/report.html` - Visual dashboard
- `psadt_scan_[timestamp]/findings.json` - Detailed JSON data

### Review Results
- ✅ **APPROVED** - Package is secure, ready for deployment
- ❌ **REJECTED** - Package has security issues, fix before deployment

### Fix Issues
Review remediation steps in the report and update package.

## Package Structure Expected

```
MyPSADTPackage/
├── Deploy-Application.ps1              ← Scanned for patterns
├── Deploy-Application.exe
├── AppDeployToolkit/
│   ├── AppDeployToolkitMain.ps1        ← Scanned
│   ├── AppDeployToolkitConfig.xml      ← Scanned
│   └── AppDeployToolkitExtensions.ps1  ← Scanned
├── SupportFiles/
│   ├── app.exe                         ← Binary analysis
│   ├── app.dll                         ← Binary analysis
│   └── config.xml                      ← Credential scan
└── Files/
    └── [install files]
```

## Scan Categories

### 1. PowerShell Analysis
Detects dangerous patterns in PS scripts:
- Hardcoded credentials
- Code injection (Invoke-Expression)
- Registry manipulation
- UAC bypass
- Event log clearing
- Lateral movement
- External downloads

### 2. Binary Analysis
Analyzes .exe and .dll files:
- Signature verification
- Suspicious imports
- Packed/obfuscated code

### 3. Credential Detection
Finds embedded secrets:
- Plain text passwords
- Base64-encoded keys
- Connection strings
- API keys

### 4. Malware Patterns
Checks for:
- C2 (Command & Control) indicators
- Malware keywords
- Suspicious behavior patterns

## Example Reports

### APPROVED Package
```
SCAN RESULTS
================================================================================

📊 SUMMARY:
   Total Issues Found: 0
   🔴 CRITICAL: 0
   🟠 HIGH: 0
   🟡 MEDIUM: 0
   🔵 LOW: 0

🔐 DECISION: APPROVED

✅ PACKAGE APPROVED FOR DEPLOYMENT
```

### REJECTED Package
```
SCAN RESULTS
================================================================================

📊 SUMMARY:
   Total Issues Found: 3
   🔴 CRITICAL: 2
   🟠 HIGH: 1
   🟡 MEDIUM: 0
   🔵 LOW: 0

🔐 DECISION: REJECTED

❌ PACKAGE BLOCKED FROM DEPLOYMENT

Required fixes:
   • hardcoded_credential: Move to SCCM Task Sequence Variable
   • registry_manipulation: Document business justification
```

## Integration with SCCM

### Automated Quality Gate
```bash
# Add to CI/CD pipeline or packaging workflow
python src/scanners/scan_psadt.py "$PACKAGE_PATH"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    # Deploy to SCCM
    sccm-deploy.exe "$PACKAGE_PATH"
else
    # Block deployment
    echo "REJECTED - Fix security issues first"
    exit 1
fi
```

## Configuration

Edit `config/rules.yaml` to:
- Adjust severity levels
- Add custom patterns
- Exclude false positives
- Add company-specific rules

## Exit Codes

```
0 = APPROVED (safe to deploy)
1 = REJECTED (security issues found)
```

## Support

For issues or questions:
- Review findings.json for detailed results
- Check report.html for visual dashboard
- Review config/rules.yaml for pattern customization

---

**Status**: Production Ready  
**Version**: 1.0  
**Last Updated**: May 27, 2026
