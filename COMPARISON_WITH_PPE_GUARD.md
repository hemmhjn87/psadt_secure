# PPE-Guard vs PSADT-Secure: Which Tool to Use?

## 📊 Comparison Matrix

| Aspect | PPE-Guard | PSADT-Secure |
|--------|-----------|--------------|
| **Purpose** | General CI/CD security | PSADT v4 specific |
| **Scan Type** | Broad enterprise scanning | Focused PSADT scanning |
| **Tools** | 7 integrated tools | 4 focused tools |
| **Scan Time** | 10-30 minutes | 2-10 minutes |
| **Best For** | Diverse packages | PSADT packages only |
| **Learning Curve** | Moderate | Easy |
| **Setup Time** | 30 minutes | 5 minutes |

---

## 🎯 When to Use Each

### Use **PPE-Guard** When:
- ✅ Scanning mixed package types (PowerShell, Python, Node, Java, etc.)
- ✅ Need comprehensive supply chain security
- ✅ Want multiple layers of defense
- ✅ Checking for PPE attacks specifically
- ✅ Enterprise-wide security program
- ✅ Full compliance audit needed

**Example**: Safran Corporate using for all software packages

### Use **PSADT-Secure** When:
- ✅ **Packaging PSADT v4 packages only**
- ✅ Want fast, focused PSADT scanning
- ✅ Need PSADT-specific rule sets
- ✅ Integration with SCCM deployment pipeline
- ✅ Packaging factory quality control
- ✅ Need quick decision (APPROVE/REJECT)

**Example**: Safran Digit Packaging Factory using for all PSADT deployments

---

## 🔄 Integration Pattern

```
Safran Digit Packaging Factory Workflow:

PSADT Package Created
        ↓
   [PSADT-Secure]  ← FIRST: Fast PSADT-specific check
        ↓
   APPROVED? → YES → [SCCM Deployment]
        ↓ NO
   [Fix Issues]
        ↓
   [Resubmit]

Optional Secondary Check:
        ↓
   [PPE-Guard]     ← OPTIONAL: Broader security check
        ↓
   Final Deployment to Production
```

---

## 📈 Feature Comparison

### Security Detection

| Detection Type | PPE-Guard | PSADT-Secure |
|---|---|---|
| Hardcoded credentials | ✅ | ✅ |
| Vulnerable dependencies | ✅ | ❌ |
| PSADT-specific attacks | ✅ | ✅✅ (Better) |
| Malware signatures | ✅ | ✅ |
| Binary analysis | ✅ | ✅✅ (Focused) |
| PowerShell patterns | ✅ | ✅✅ (Better) |
| Git history secrets | ✅ | ❌ |
| XML vulnerabilities | ✅ | ✅ |
| Certificate checks | ❌ | ✅ |

### Reporting

| Type | PPE-Guard | PSADT-Secure |
|---|---|---|
| Executive dashboard | ✅ | ✅ |
| Technical details | ✅ | ✅ |
| Remediation guidance | ✅ | ✅ |
| JSON export | ✅ | ✅ |
| HTML report | ✅ | ✅ |
| Severity scoring | ✅ | ✅ |

### Integration

| Target | PPE-Guard | PSADT-Secure |
|---|---|---|
| SCCM | ✅ | ✅✅ (Native) |
| GitHub Actions | ✅ | ✅ |
| Azure DevOps | ✅ | ✅ |
| Jenkins | ✅ | ✅ |
| GitLab CI | ✅ | ✅ |

---

## 🚀 Recommendation for Safran Digit

### **Primary: PSADT-Secure**
```
Why: 
  • All packages are PSADT v4
  • Need quick packaging factory decisions
  • Focus on PSADT-specific issues
  • Minimal false positives

Usage:
  python main.py "C:\Packages\NewApp"
  
Decision: APPROVE → Deploy | REJECT → Fix & Resubmit
```

### **Optional Secondary: PPE-Guard**
```
Why:
  • Broader security coverage
  • Catch supply chain attacks
  • Executive reporting
  
When:
  • Before major releases
  • Security audits
  • Compliance reviews
```

---

## 💻 Quick Command Reference

### PSADT-Secure (Fast)
```bash
python d:\project\psadt-secure\main.py "C:\Packages\MyApp"
```
Output: Decision in 2-10 minutes

### PPE-Guard (Comprehensive)
```bash
python d:\project\ppe-guard\src\scanners\scan_all.py "C:\Packages"
```
Output: Full report in 10-30 minutes

---

## 📊 Performance Comparison

| Scenario | PSADT-Secure | PPE-Guard |
|----------|---|---|
| Single PSADT package | 2-5 min | 5-15 min |
| 10 PSADT packages | 20-50 min | 50-150 min |
| 100 diverse packages | N/A | 5-10 hours |

---

## 🎯 Decision Tree

```
Scanning PSADT v4 package?
    ↓ YES
    └─→ Use PSADT-Secure (Fast & Focused)
    
    ↓ NO (Other package types)
    └─→ Use PPE-Guard (Comprehensive)

Need both?
    └─→ PSADT-Secure first (quality gate)
        └─→ PPE-Guard second (compliance)
```

---

## 🔧 Configuration

### PSADT-Secure Config
```bash
# Single file to customize
d:\project\psadt-secure\config\rules.yaml
```
Edit to add:
- PSADT-specific patterns
- Company policies
- Exception rules

### PPE-Guard Config
```bash
# Multiple configuration files
d:\project\ppe-guard\config\
├── semgrep.yml
├── policies.rego
└── custom_rules.yaml
```

---

## 💡 Best Practice: Layered Approach

```
Every PSADT Package Deployment:

1st Layer: PSADT-Secure
   ├─ Fast (5 min)
   ├─ PSADT-specific
   └─ APPROVE/REJECT decision

2nd Layer (Optional): Full Testing
   ├─ Functional testing
   ├─ Integration testing
   └─ Business acceptance

3rd Layer (Periodic): PPE-Guard
   ├─ Monthly/quarterly
   ├─ Broader security check
   ├─ Compliance audit
   └─ Executive reporting
```

---

## 📈 Rollout Recommendation

### Week 1: PSADT-Secure
```
- Deploy PSADT-Secure to packaging factory
- Run on all new packages
- Team training (1 hour)
- Collect baseline findings
```

### Week 2-4: Tune & Optimize
```
- Adjust rules based on findings
- Integrate with CI/CD
- Add to release checklist
- Monitor false positive rate
```

### Month 2: Consider PPE-Guard
```
- Optional secondary scan
- Monthly compliance audits
- Executive dashboards
- Trend analysis
```

---

## ✅ Summary

| Need | Tool | Time | Reason |
|------|------|------|--------|
| PSADT quality gate | **PSADT-Secure** | 5 min | Fast, focused |
| SCCM deployment check | **PSADT-Secure** | 5 min | PSADT-native |
| Mixed packages | **PPE-Guard** | 15 min | Comprehensive |
| Compliance audit | **PPE-Guard** | 30 min | Full coverage |
| Both? | **Both** | 20 min | Best defense |

---

## 🎯 For Safran Digit Packaging Factory

**IMMEDIATE**: Use **PSADT-Secure** for all PSADT v4 deployments

**Command**:
```bash
python d:\project\psadt-secure\main.py "C:\SCCM\Packages\YourApp"
```

**Decision**: APPROVED → Deploy | REJECTED → Fix & Resubmit

---

**Created**: May 27, 2026  
**Status**: Ready for Production  
**Recommendation**: Start with PSADT-Secure TODAY
