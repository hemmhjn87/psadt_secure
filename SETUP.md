# HemSpect: Installation & Setup Guide

## System Requirements

- Python 3.8+
- Windows 10+ / Windows Server 2016+
- PowerShell 5.1+ (for PSScriptAnalyzer integration)
- 500 MB disk space
- pip (Python package manager)

## Step 1: Clone the Project

```bash
cd d:\project
# Project already exists at d:\project\hemspect
cd hemspect
```

## Step 2: Create Virtual Environment (Optional but Recommended)

```bash
# Create venv
python -m venv venv

# Activate venv
# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate
```

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed**:
- `pefile` - Windows PE file analysis
- `detect-secrets` - Credential detection
- `yara-python` - Malware pattern matching
- `semgrep` - SAST pattern analysis
- Other utilities (YAML, requests, click, colorama)

**Installation time**: 2-5 minutes

## Step 4: Verify Installation

```bash
python main.py
```

Should show usage instructions.

## Step 5: Run First Scan

```bash
# Create test directory (optional)
mkdir test_packages

# Scan
python main.py test_packages
```

## Troubleshooting

### Error: "No module named 'pefile'"
```bash
pip install pefile
```

### Error: "No module named 'yara'"
```bash
pip install yara-python
```

### Error: "No module named 'detect_secrets'"
```bash
pip install detect-secrets
```

### Error: "Access Denied" when scanning
Run Command Prompt as Administrator, then retry.

## Post-Installation Configuration

### 1. Customize Rules

Edit `config/rules.yaml` to add:
- Company-specific patterns
- Additional severity rules
- False positive exclusions

### 2. Set Output Directory

Default: `psadt_scan_[timestamp]/`

To change, modify in `src/scanners/scan_psadt.py`:
```python
self.output_dir = Path(output_dir or f"psadt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
```

### 3. Integration with SCCM

Create a wrapper script to automate:
```powershell
# scan_psadt.ps1
param([string]$PackagePath)
python main.py $PackagePath
if ($LASTEXITCODE -eq 0) {
    Write-Host "APPROVED" -ForegroundColor Green
} else {
    Write-Host "REJECTED" -ForegroundColor Red
}
```

## Daily Usage

```bash
# Simple scan
python main.py "C:\SCCM\Packages\MyApp"

# With custom output
python main.py "C:\SCCM\Packages\MyApp" "C:\Reports\2026-05-27"

# Batch scan all packages
for /D %G in (C:\SCCM\Packages\*) do (
    python main.py "%G"
)
```

## Support

- **Issues**: Check findings.json for detailed results
- **Questions**: Review README.md
- **Customization**: Edit config/rules.yaml

---

**Setup Complete!** You're ready to scan PSADT packages.
