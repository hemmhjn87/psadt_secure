# PSADT-Secure v3.0 — Allowlist Policy

> **Document Type**: Security Policy  
> **Version**: 1.0  
> **Owner**: Security Operations  
> **Approval**: CISO  
> **Review Cycle**: Quarterly  

---

## 1. Purpose

This policy establishes the framework for managing **exception allowlists** in PSADT-Secure scanning. An allowlist exception suppresses a specific scanner finding for a specific file, based on documented business justification and formal approval.

Allowlisting is a **risk acceptance mechanism** — it does not eliminate the security risk; it documents that a qualified person has reviewed and accepted the risk with appropriate controls in place.

---

## 2. Scope

Applies to all PSADT v4 packages scanned with PSADT-Secure in any of the following environments:
- Pre-deployment security review
- CI/CD pipeline integration
- Periodic re-scanning of deployed packages

---

## 3. Exception Categories

### 3.1 Approved Exception Types

| Category | Example | Approval Level |
|----------|---------|---------------|
| False Positive | `registry_manipulation` flagged for expected app config keys | SOC Analyst |
| Accepted Risk — Low | `wmi_query` for hardware inventory | SOC Analyst |
| Accepted Risk — Medium | `external_download` from controlled internal server | Senior Analyst + CISO notification |
| Accepted Risk — High | `scheduled_task` for licensed software requirement | CISO authorization number required |
| Vendor Exception | Binary must be unsigned due to vendor limitation (temporary) | CISO + 30-day max |

### 3.2 Non-Allowlistable Patterns (Absolute Prohibition)

The following patterns **may never be allowlisted** under any circumstances. These represent active attack techniques or malware indicators:

| Pattern | Reason |
|---------|--------|
| `credential_dumping` | Mimikatz / LSASS dump — always malicious in deployment packages |
| `amsi_patch_memory` | AMSI bypass — disables security monitoring |
| `amsi_reflection` | AMSI bypass via reflection |
| `amsi_script_bypass` | AMSI bypass |
| `etw_tampering` | Disables Event Tracing for Windows |
| `c2_ip` | Command and Control communication |
| `suspicious_strings` | Direct malware keyword match |
| `data_exfiltration` | Data theft indicators |
| `process_injection` | Code injection |
| `privilege_escalation` | SeDebugPrivilege abuse |

**If any of these are found and cannot be resolved:** The package must be **REJECTED** and escalated to Incident Response for investigation.

---

## 4. Exception Request Process

```
1. Packaging Team identifies finding in scan report
         │
         ▼
2. SOC Analyst reviews finding in context
   - Is it a True Positive or False Positive?
   - What is the actual risk?
         │
         ├── FALSE POSITIVE ──► Document as FP with evidence
         │                      SOC Analyst adds allowlist entry
         │                      No ticket required if clear FP
         │
         └── TRUE POSITIVE ──► Risk Assessment Required
                 │
                 ▼
         3. Raise change ticket (CHG-XXXX)
            Document: business justification, compensating controls
                 │
                 ▼
         4. Approval based on severity:
            - LOW/MEDIUM: Senior SOC Analyst
            - HIGH: CISO or delegate
            - CRITICAL: REJECTED — no exceptions
                 │
                 ▼
         5. Add to allowlist.yaml with all required fields
            Maximum validity: 365 days
                 │
                 ▼
         6. Re-run scan to confirm suppression works
         7. Document in ticket that exception added
```

---

## 5. Allowlist Entry Requirements

Every exception entry in `config/allowlist.yaml` MUST contain:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | ✅ | Unique exception ID (e.g., exc-001) |
| `rule_id` | ✅ | Exact scanner rule ID |
| `file_pattern` | ✅ | File name or glob pattern |
| `approved_by` | ✅ | Approver's full name or employee ID |
| `approved_date` | ✅ | ISO date (YYYY-MM-DD) |
| `ticket` | ✅ | Change/exception ticket number |
| `expiry` | ✅ | ISO date (max 365 days from approval) |
| `justification` | ✅ | Min 20 characters explaining the risk acceptance |
| `risk_accepted` | ✅ | Residual risk level (LOW/MEDIUM) |
| `match_contains` | Optional | Only suppress if the matched string contains this value |

**Example compliant entry:**
```yaml
exceptions:
  - id: exc-007
    rule_id: external_download
    file_pattern: "Deploy-Application.ps1"
    match_contains: "packages.internal.corp.com"
    approved_by: "J.Smith-CISO"
    approved_date: "2026-06-01"
    ticket: "CHG-2026-0789"
    expiry: "2026-11-30"
    justification: >
      Package downloads MSI from internal distribution server
      (packages.internal.corp.com). Server is on isolated VLAN,
      TLS 1.3 enforced, hash validation performed post-download.
      Network path monitored by SOC (ticket INC-2026-0001).
    risk_accepted: "LOW - internal controlled endpoint, hash validated"
```

---

## 6. Exception Lifecycle

### 6.1 Creation
- Add to `config/allowlist.yaml` following the schema
- Submit PR/change request for peer review
- Minimum: second-pair-of-eyes from another SOC analyst

### 6.2 Maintenance
- Scanner automatically rejects expired exceptions (past `expiry` date)
- Weekly automated report of expiring exceptions (within 30 days)
- Exception owner is notified 14 days before expiry

### 6.3 Renewal
- Exceptions may be renewed for up to 365 additional days
- Renewal requires fresh approval at same approval level
- Renewing same exception 3+ times triggers mandatory risk review

### 6.4 Revocation
- Any exception can be revoked immediately by updating `expiry` to past date
- Revoking an exception will cause next scan to flag the finding again
- Revocation should be recorded in the ticket log

---

## 7. Audit Requirements

The allowlist system maintains the following audit records:

1. **Scanner audit log** (`audit.log` JSONL): Every scan records which exceptions were applied, with the exception ID and the finding it suppressed
2. **Git history**: `allowlist.yaml` should be version-controlled; git log provides addition/removal history
3. **Report**: Each scan report shows a "Suppressed Findings" section listing all allowlisted items
4. **Quarterly review**: SOC team reviews all active exceptions; remove expired or no longer needed entries

---

## 8. Violations

Circumventing this policy (e.g., adding blanket allowlist patterns, creating fake tickets, setting expiry dates far in the future) is a security policy violation subject to:
- Immediate removal of allowlist contribution access
- Escalation to HR and management
- Potential regulatory reporting if the deployment environment is subject to CMMC or IEC 62443 audits

---

*Policy Owner: Security Operations*  
*Last Approved: 2026-06-01*  
*Next Review: 2026-09-01*
