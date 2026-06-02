# HemSpect v3.0 — Compliance Standards Reference

> **Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY  
> **Document Version**: 3.0.0  
> **Last Reviewed**: 2026-06-01  
> **Applicable Standards**: NIST SP 800-53 Rev5, CMMC 2.0, IEC 62443-2-4, CIS Controls v8, OWASP Top 10 2021

---

## 1. Executive Overview

HemSpect v3.0 is designed to meet the security vetting requirements of aerospace, defense, and critical-infrastructure organizations, including suppliers and subcontractors operating under:

- **Boeing** Enterprise Software Packaging Standards (BSPS)
- **Safran** Digital Security Policy (DSP-SEC-001)
- **DoD** Cybersecurity Maturity Model Certification (CMMC 2.0 Level 2/3)
- **EU Aviation** NIS2 Directive supply-chain requirements
- **IEC 62443** Industrial Control System security requirements

Every scanner finding is tagged to the applicable control framework identifiers, enabling direct traceability from vulnerability to compliance obligation.

---

## 2. NIST SP 800-53 Rev5 Control Mapping

### SI — System and Information Integrity

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| SI-2 | Flaw Remediation | NVD CVE lookup for all binaries |
| SI-3 | Malware Protection | Malware pattern detection, LOLBin abuse |
| SI-3(2) | Automatic Updates | External download detection |
| SI-7 | Software, Firmware, and Information Integrity | Authenticode chain validation, ECDSA manifest |
| SI-7(1) | Integrity Checks | SHA-256/512 hash manifest for all files |
| SI-7(6) | Cryptographic Protection | Cryptographic manifest signing |
| SI-10 | Information Input Validation | Invoke-Expression, unvalidated path injection |
| SI-12 | Information Management and Retention | Cleartext credential storage |

### CM — Configuration Management

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| CM-6 | Configuration Settings | Registry manipulation, UAC bypass |
| CM-7 | Least Functionality | LOLBin, service creation, scheduled tasks |
| CM-7(4) | Unauthorized Software | Unsigned binary detection |
| CM-7(5) | Authorized Software | Allowlist engine |
| CM-8(3) | Automated Unauthorized Component Detection | SBOM generation and tracking |

### AC — Access Control

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| AC-3 | Access Enforcement | Hardcoded credentials, privilege escalation |
| AC-6 | Least Privilege | UAC bypass, SeDebugPrivilege abuse |
| AC-6(1) | Authorize Access to Security Functions | PSCredential with embedded passwords |
| AC-17 | Remote Access | Lateral movement, WinRM abuse |

### AU — Audit and Accountability

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| AU-2 | Event Logging | Event log clearing detection |
| AU-3 | Content of Audit Records | Tamper-evident JSONL audit log |
| AU-9 | Protection of Audit Information | Event log clearing, ETW tampering |
| AU-12 | Audit Record Generation | AMSI bypass, ETW tampering |

### IA — Identification and Authentication

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| IA-5 | Authenticator Management | Hardcoded credentials, API keys |
| IA-5(6) | Protection of Authenticators | Plaintext SecureString |

### SA — System and Services Acquisition

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| SA-11 | Developer Testing and Evaluation | All code-level detections |
| SA-12 | Supply Chain Protection | SBOM generation, NVD CVE lookup |
| SA-15 | Development Process | Obfuscation, credential embedding |

### SC — System and Communications Protection

| Control | Title | Scanner Coverage |
|---------|-------|-----------------|
| SC-7 | Boundary Protection | External download, C2 IP detection |
| SC-18 | Mobile Code | External downloads, COM object abuse |
| SC-28 | Protection of Information at Rest | Cleartext credential storage |

---

## 3. CMMC 2.0 Control Mapping

### Level 1 (17 Practices)

| Practice ID | Title | Scanner Coverage |
|-------------|-------|-----------------|
| AC.1.001 | Limit information system access | UAC bypass, privilege escalation |
| AC.1.002 | Limit information system access to authorized transactions | Lateral movement |
| SI.1.210 | Identify, report, and correct information and information system flaws | All vulnerability detections |

### Level 2 (110 Practices — Key Subset)

| Practice ID | Title | Scanner Coverage |
|-------------|-------|-----------------|
| AC.2.006 | Limit use of portable storage devices | External download patterns |
| AC.2.007 | Employ principle of least privilege | UAC bypass, admin credential embedding |
| AU.2.041 | Ensure audit logs are protected | Event log clearing, ETW tampering |
| AU.2.042 | Create and retain system audit logs | Audit log generation |
| AU.3.045 | Review and update logged events | Comprehensive audit log |
| AU.3.046 | Alert in the event of audit process failure | Tamper-evident chain |
| CM.2.061 | Establish and maintain baseline configurations | Registry, service, task creation |
| CM.2.064 | Establish and enforce security configuration settings | Disabled security features |
| IA.3.083 | Use multifactor authentication | Hardcoded credential detection |
| SC.3.177 | Employ FIPS-validated cryptography | Cryptographic manifest (ECDSA P-256) |
| SI.2.214 | Provide protection from malicious code | Malware pattern, AMSI bypass |
| SA.4.171 | Employ code analysis tools | All static analysis patterns |

---

## 4. IEC 62443-2-4 Mapping (Industrial Cybersecurity)

Applicable when PSADT packages are deployed in OT/ICS environments:

| Requirement | Title | Scanner Coverage |
|-------------|-------|-----------------|
| SR 1.1 | Human user identification and authentication | Credential embedding |
| SR 1.2 | Software process and device identification | Service/task creation |
| SR 1.3 | Account management | PSCredential patterns |
| SR 2.1 | Authorization enforcement | UAC bypass, privilege escalation |
| SR 3.1 | Communication integrity | Lateral movement, WinRM |
| SR 3.2 | Malicious code protection | All malware patterns |
| SR 3.4 | Software and information integrity | Code injection, Invoke-Expression |
| SR 3.8 | Session integrity | AMSI bypass, ETW tampering |
| SR 4.1 | Information confidentiality | Cleartext credentials |
| SR 5.2 | Zone boundary protection | External downloads, C2 IP |
| SR 6.1 | Audit log accessibility | Event log clearing |
| SR 6.2 | Continuous monitoring | Tamper-evident audit chain |
| SR 7.6 | Network and security configuration settings | Registry manipulation |

---

## 5. CIS Controls v8 Mapping

| CIS Control | Title | Scanner Coverage |
|-------------|-------|-----------------|
| CIS-2 | Inventory and Control of Software Assets | SBOM generation, unsigned binary |
| CIS-2.3 | Address Unauthorized Software | LOLBin, unwhitelisted downloads |
| CIS-2.5 | Allowlist Authorized Software | Allowlist engine, AppLocker patterns |
| CIS-3.11 | Encrypt Sensitive Data at Rest | Plaintext credentials |
| CIS-4.1 | Establish and Maintain Secure Configuration | Registry, UAC, service patterns |
| CIS-4.8 | Uninstall or Disable Unnecessary Services | Service creation patterns |
| CIS-5.1 | Establish and Maintain an Inventory of Accounts | Credential creation patterns |
| CIS-5.4 | Restrict Administrator Privileges | UAC bypass, privilege escalation |
| CIS-7.3 | Perform Automated Operating System Patch Management | Malware patterns, LOLBin |
| CIS-7.4 | Perform Automated Application Patch Management | NVD CVE lookup |
| CIS-8.2 | Collect Audit Logs | Event log clearing, ETW tampering |
| CIS-8.5 | Collect Detailed Audit Logs | Registry audit patterns |
| CIS-9.2 | Use DNS Filtering Services | C2 IP detection, external download |
| CIS-10.1 | Deploy and Maintain Anti-Malware Software | AMSI bypass, disabled security |
| CIS-10.2 | Configure Automatic Anti-Malware Scanning | Disabled defender patterns |
| CIS-12.2 | Establish and Maintain a Secure Network Architecture | Lateral movement |
| CIS-13.1 | Centralize Security Event Alerting | Event log clearing |
| CIS-13.6 | Collect Network Traffic Flow Logs | External downloads |
| CIS-16.2 | Establish and Maintain a Process to Accept and Address Reports | Credential reports |
| CIS-16.9 | Train Developers in Application Security Concepts | Remediation guidance |

---

## 6. OWASP Top 10 2021 Mapping

| OWASP | Title | Scanner Coverage |
|-------|-------|-----------------|
| A01:2021 | Broken Access Control | UAC bypass, lateral movement |
| A02:2021 | Cryptographic Failures | Hardcoded credentials, plaintext secrets |
| A03:2021 | Injection | Invoke-Expression, code injection, LOLBin |
| A05:2021 | Security Misconfiguration | Registry, UAC, disabled security |
| A07:2021 | Identification and Authentication Failures | Credential patterns |
| A08:2021 | Software and Data Integrity Failures | Unsigned binaries, AMSI bypass |
| A09:2021 | Security Logging and Monitoring Failures | Event log clearing, ETW tampering |

---

## 7. CVSS v3.1 Scoring Methodology

Each finding includes a CVSS v3.1 base score calculated using the following vectors:

| Vector | Description |
|--------|-------------|
| AV (Attack Vector) | L=Local, N=Network, P=Physical, A=Adjacent |
| AC (Attack Complexity) | L=Low, H=High |
| PR (Privileges Required) | N=None, L=Low, H=High |
| UI (User Interaction) | N=None, R=Required |
| S (Scope) | U=Unchanged, C=Changed |
| C (Confidentiality) | N=None, L=Low, H=High |
| I (Integrity) | N=None, L=Low, H=High |
| A (Availability) | N=None, L=Low, H=High |

### Example Scores

| Pattern | CVSS Score | Vector |
|---------|-----------|--------|
| hardcoded_credential | 9.1 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| invoke_expression | 8.8 HIGH | AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| uac_bypass | 8.8 HIGH | AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| amsi_patch_memory | 9.8 CRITICAL | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| credential_dumping | 7.8 HIGH | AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N |
| external_download | 8.8 HIGH | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H |
| lolbin_certutil_decode | 8.8 HIGH | AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N |

---

## 8. Aerospace-Specific Requirements

### Boeing Software Packaging Standards
- All deployment packages must pass SI-7 integrity verification
- Authenticode signatures required from approved Boeing CA
- SBOM required for all third-party components
- Zero tolerance for hardcoded credentials (automatic REJECTED status)

### Safran Digital Security Policy (DSP-SEC-001)
- Package security assessment required before Change Advisory Board (CAB) approval
- CRITICAL findings: 48-hour remediation SLA
- HIGH findings: 5 business day remediation SLA  
- SBOM must be retained for 5 years
- Audit log must be retained for 3 years

### DoD/CMMC Requirements
- FIPS 140-2 validated cryptography for all signing operations
- Supply chain risk management (SCRM) - CVE check for all components
- Operator authentication via PKI certificate (CAC/PIV) recommended

---

## 9. Approval Thresholds

| Organization Tier | CRITICAL | HIGH | MEDIUM | RISK SCORE |
|-------------------|----------|------|--------|------------|
| **Standard Enterprise** | 0 | 0 | ≤5 | <30 |
| **Aerospace / Defense** | 0 | 0 | 0 | <20 |
| **Safety-Critical / OT** | 0 | 0 | 0 | <10 |

> [!CAUTION]
> For safety-critical systems (flight control, avionics support), the threshold is **zero findings of any severity** before manual CISO review.

---

## 10. Regulatory References

| Standard | Title | Relevant Sections |
|----------|-------|-------------------|
| NIST SP 800-53 Rev5 | Security and Privacy Controls for IS | SI, CM, AC, AU families |
| NIST SP 800-167 | Guide to Application Whitelisting | Section 3, 4 |
| NIST SP 800-161r1 | C-SCRM Practices | Chapter 3 |
| CMMC 2.0 Assessment Guide | Level 2 | All SI and CM domains |
| IEC 62443-2-4:2015 | IACS SP Requirements | SR 1-7 |
| ISO/IEC 27001:2022 | ISMS Requirements | Annex A.8, A.12 |
| OWASP ASVS 4.0 | Application Security Verification | V2, V5, V7 |
| CIS Benchmark | Windows Server 2022 | Sections 2, 9, 17 |
| BSI TR-02102-1 | Cryptographic Mechanisms | ECDSA P-256 validation |

---

*Document maintained by: Security Operations — HemSpect Project*  
*Review cycle: Quarterly or upon new CVE/ATT&CK framework release*
