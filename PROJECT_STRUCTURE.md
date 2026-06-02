# HemSpect: Project Structure

```
hemspect/
│
├── 📄 README.md                    # Project overview
├── 📄 QUICK_START.md              # 5-minute quick start
├── 📄 SETUP.md                    # Installation guide
├── 📄 requirements.txt            # Python dependencies
├── 🐍 main.py                     # Entry point
│
├── 📁 src/
│   ├── __init__.py
│   └── 📁 scanners/
│       ├── __init__.py
│       └── 🐍 scan_psadt.py       # Main scanner (1000+ lines)
│
├── 📁 config/
│   └── 📄 rules.yaml              # Security rules
│
├── 📁 docs/
│   ├── 📄 ARCHITECTURE.md         # Technical design
│   ├── 📄 REMEDIATION.md          # How to fix issues
│   └── 📄 INTEGRATION.md          # SCCM integration
│
└── 📁 reports/
    └── [scan results generated here]
```

## Key Files

### **main.py** (Entry Point)
```
Simple entry point to run scanner
$ python main.py <package_path> [output_dir]
```

### **src/scanners/scan_psadt.py** (Main Scanner)
```
Core scanning logic:
  - PSScriptAnalyzer integration
  - Binary analysis (pefile)
  - Credential detection (detect-secrets)
  - Malware patterns (yara)
  - PSADT-specific rules
  - HTML/JSON reporting
```

### **config/rules.yaml** (Configuration)
```
Security patterns and rules:
  - Critical patterns (hardcoded creds, UAC bypass)
  - High patterns (lateral movement)
  - Medium patterns (registry changes)
  - Binary analysis rules
  - Credential patterns
```

## Workflow

```
Package
   ↓
[main.py]
   ↓
[scan_psadt.py]
   ├─ Read Deploy-Application.ps1
   ├─ Apply PSADT rules
   ├─ Analyze binaries
   ├─ Detect credentials
   ├─ Check malware
   └─ Aggregate findings
   ↓
[Generate Reports]
   ├─ report.html (visual)
   ├─ findings.json (data)
   └─ print_summary() (console)
   ↓
[APPROVED / REJECTED]
```

## Usage Examples

### Basic Scan
```bash
python main.py "C:\SCCM\Packages\MyApp"
```

### Custom Output Directory
```bash
python main.py "C:\SCCM\Packages\MyApp" "C:\MyReports"
```

### Batch Processing
```bash
for /D %pkg in (C:\SCCM\Packages\*) do python main.py "%pkg"
```

### CI/CD Integration
```bash
python main.py "$PACKAGE" && echo "OK" || echo "FAILED"
```

## Output

Each scan generates:
```
psadt_scan_20260527_153045/
├── report.html         # Visual dashboard
├── findings.json       # Machine-readable results
└── [scan logs]
```

---

**Project Status**: Production Ready  
**Version**: 1.0  
**Created**: May 27, 2026
