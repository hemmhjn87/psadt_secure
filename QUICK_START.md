# PSADT-Secure: Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Install (2 min)
```bash
cd d:\project\psadt-secure
pip install -r requirements.txt
```

### Step 2: Scan Package (2 min)
```bash
python src/scanners/scan_psadt.py "C:\SCCM\Packages\MyPackage"
```

### Step 3: Review Report (1 min)
```bash
# Open in browser
open psadt_scan_[timestamp]/report.html
```

---

## 📋 Common Commands

### Scan with custom output directory
```bash
python src/scanners/scan_psadt.py "C:\Packages\App" "C:\Reports"
```

### Scan all packages
```bash
for pkg in C:\SCCM\Packages\*; do
  echo "Scanning: $pkg"
  python src/scanners/scan_psadt.py "$pkg"
done
```

### Integration with CI/CD
```bash
python src/scanners/scan_psadt.py "$1" && echo "APPROVED" || echo "REJECTED"
```

---

## 🔍 What It Scans

| Issue | Severity | Example |
|-------|----------|---------|
| Hardcoded password | 🔴 CRITICAL | `$password = "MyPass123"` |
| Unsigned binary | 🟠 HIGH | app.exe without signature |
| API key embedded | 🔴 CRITICAL | `api_key = "sk_test_..."` |
| UAC bypass | 🔴 CRITICAL | `Set-ItemProperty.*EnableLUA.*0` |
| Event log clearing | 🔴 CRITICAL | `Clear-EventLog` |
| Remote execution | 🟠 HIGH | `Invoke-Command -ComputerName` |

---

## ✅ APPROVED Package Example

```
✅ PACKAGE APPROVED FOR DEPLOYMENT

No security issues found - ready for SCCM deployment
```

---

## ❌ REJECTED Package Example

```
❌ PACKAGE BLOCKED FROM DEPLOYMENT

Issues found:
  1. Line 145 in Deploy-Application.ps1: Hardcoded password
     → Fix: Use SCCM Task Sequence Variable
  
  2. app.exe: Unsigned executable
     → Fix: Sign with company certificate
  
  3. Line 78: Event log clearing detected
     → Fix: Remove log clearing code
```

---

## 📊 Output Files

After each scan, you get:

1. **report.html** - Visual dashboard (open in browser)
2. **findings.json** - Detailed data (for automation)
3. **scan_psadt.log** - Scan execution log

---

## 🛠️ Troubleshooting

### "pefile not found"
```bash
pip install pefile
```

### "No issues found" but package looks suspicious
Review the raw findings in `findings.json` for details.

### "Permission denied" errors
Run PowerShell as Administrator.

---

## 🎯 Quick Reference

| Command | Purpose |
|---------|---------|
| `scan_psadt.py <path>` | Scan single package |
| `report.html` | View results in browser |
| `findings.json` | Machine-readable results |
| Exit code 0 | APPROVED |
| Exit code 1 | REJECTED |

---

**Version**: 1.0  
**Status**: Ready for Production  
**Created**: May 27, 2026
