# Security Patterns Reference - HemSpect v2.0

## PowerShell Security Patterns (20+)

### 🔴 CRITICAL Severity Patterns

#### 1. Hardcoded Credentials
```
Pattern: $password = "..."
Risk: CWE-798 (Hard-coded Credentials)
MITRE: T1110 (Brute Force)
Remediation: Move to SCCM TS Variable (mark Private) or Azure Key Vault
Example:
  ❌ Bad:  $password = "MySecretPassword123"
  ✅ Good: $password = $TSEnv:PasswordVariable
```

#### 2. SecureString with -AsPlainText
```
Pattern: ConvertTo-SecureString -AsPlainText -Force
Risk: CWE-312 (Cleartext Storage)
MITRE: T1552 (Unsecured Credentials)
Remediation: Remove -AsPlainText -Force flags; use credential objects
Example:
  ❌ Bad:  ConvertTo-SecureString "pass" -AsPlainText -Force
  ✅ Good: Get-Credential or use managed service accounts
```

#### 3. Invoke-Expression (Code Injection)
```
Pattern: Invoke-Expression $...
Risk: CWE-95 (Improper Neutralization)
MITRE: T1086 (Command Line Interface)
Remediation: Use -ScriptBlock parameter with type validation
Example:
  ❌ Bad:  Invoke-Expression $userInput
  ✅ Good: & $commandBlock @parameters
```

#### 4. UAC Bypass
```
Pattern: EnableLUA.*0 or UAC.*disable
Risk: CWE-648 (Incorrect Resource Validation)
MITRE: T1088 (Bypass User Account Control)
Remediation: Remove UAC bypass; use SCCM elevation
Example:
  ❌ Bad:  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0
  ✅ Good: Use SCCM with elevated context
```

#### 5. Event Log Clearing
```
Pattern: Clear-EventLog or Remove-Item.*Logs
Risk: CWE-612 (Improper Restriction of Rendered UI Layers)
MITRE: T1070 (Clear Event Logs)
Remediation: Remove event log clearing; enable immutable logs
Example:
  ❌ Bad:  Clear-EventLog -LogName Security
  ✅ Good: Use proper log management via Group Policy
```

#### 6. Security Feature Disabling
```
Pattern: disable.*defender or disable.*antivirus
Risk: CWE-1104 (Use of Unmaintained Third Party Components)
MITRE: T1089 (Disable or Modify Tools)
Remediation: Keep security features enabled
Example:
  ❌ Bad:  Set-MpPreference -DisableRealtimeMonitoring $true
  ✅ Good: Don't disable security features
```

#### 7. Credential Dumping
```
Pattern: mimikatz|sekurlsa|lsadump|gsecdump
Risk: CWE-200 (Information Exposure)
MITRE: T1003 (Credential Dumping)
Remediation: Remove credential dumping tools immediately
Example:
  ❌ Bad:  .\mimikatz.exe "sekurlsa::logonpasswords"
  ✅ Good: Use authorized credential management tools
```

### 🟠 HIGH Severity Patterns

#### 8. Registry Manipulation (HKLM)
```
Pattern: Set-ItemProperty.*HKLM
Risk: CWE-1104 (Unvalidated Component Load)
MITRE: T1112 (Modify Registry)
Remediation: Document business justification; use AppLocker
Example:
  ❌ Suspicious: Set-ItemProperty HKLM:\... -Value $maliciousValue
  ✅ Reviewed: Document why registry change is needed
```

#### 9. Lateral Movement
```
Pattern: Invoke-Command -ComputerName <remote>
Risk: CWE-200 (Information Exposure)
MITRE: T1021 (Remote Services)
Remediation: Remove remote execution; use deployment servers
Example:
  ❌ Bad:  Invoke-Command -ComputerName $hostName -ScriptBlock {...}
  ✅ Good: Use SCCM deployment or approved automation
```

#### 10. External Download
```
Pattern: DownloadString|DownloadFile|System.Net.WebClient
Risk: CWE-95 (Code Injection)
MITRE: T1105 (Remote File Copy)
Remediation: Whitelist and verify URLs; package content instead
Example:
  ❌ Bad:  (New-Object System.Net.WebClient).DownloadString($url)
  ✅ Good: Include required files in package
```

#### 11. Remote Code Execution
```
Pattern: psexec|wmic.*process|wmi|winrm
Risk: CWE-200 (Information Exposure)
MITRE: T1028 (Remote Services)
Remediation: Use SCCM deployment; avoid remote execution
Example:
  ❌ Bad:  wmic /node:$computer process call create $command
  ✅ Good: Deploy via SCCM to target systems
```

#### 12. COM Object Creation
```
Pattern: New-Object.*COM|WinHttp|URLDownloadToFile
Risk: CWE-95 (Code Injection)
MITRE: T1173 (Execution through Module Load)
Remediation: Verify COM object legitimacy
Example:
  ❌ Bad:  New-Object -ComObject WinHttp.WinHttpRequest.5.1
  ✅ Good: Use modern .NET APIs instead
```

#### 13. Script Block Manipulation
```
Pattern: Invoke-Command.*-ScriptBlock.*$(...)
Risk: CWE-95 (Code Injection)
MITRE: T1086 (Command Line Interface)
Remediation: Avoid dynamic script block construction
Example:
  ❌ Bad:  Invoke-Command -ScriptBlock ([scriptblock]::Create($string))
  ✅ Good: Use explicit function calls
```

### 🟡 MEDIUM Severity Patterns

#### 14. Service Creation
```
Pattern: New-Service or Set-Service
Risk: CWE-1104 (Unvalidated Component Load)
MITRE: T1050 (New Service)
Remediation: Document service purpose; implement auto-removal
Example:
  ❌ Suspicious: New-Service -Name HiddenService -BinaryPathName $path
  ✅ Reviewed: Documented purpose and auto-cleanup
```

#### 15. Scheduled Task Creation
```
Pattern: Register-ScheduledTask
Risk: CWE-1104 (Persistence Mechanism)
MITRE: T1053 (Scheduled Task)
Remediation: Use deployment tasks; remove persistence
Example:
  ❌ Bad:  Register-ScheduledTask -TaskName Hidden -Action $action
  ✅ Good: Use proper deployment scheduling
```

#### 16. Code Obfuscation
```
Pattern: Backtick escaping, char encoding, base64
Risk: CWE-701 (Incorrect Regular Expression)
MITRE: T1027 (Obfuscation)
Remediation: Deobfuscate and verify legitimacy
Example:
  ❌ Bad:  `$vAr`iAb`Le = "obfuscated"
  ✅ Good: Clear, readable variable names
```

#### 17. Suspicious Imports
```
Pattern: LoadLibrary with dangerous DLLs
Risk: CWE-427 (Uncontrolled Search Path Element)
MITRE: T1106 (Native API)
Remediation: Review import necessity
Example:
  ❌ Suspicious: kernel32.dll::CreateRemoteThread
  ✅ Safe: Standard system imports
```

#### 18. Packed Executable
```
Pattern: High entropy (> 7.0) binary
Risk: CWE-656 (Dependence on Undefined, Unimplemented Behavior)
MITRE: T1027 (Obfuscation)
Remediation: Unpack and analyze binary content
Example:
  Entropy 6.2 = Normal executable
  Entropy 7.5 = Likely packed/compressed
```

---

## Binary Analysis Patterns

### Digital Signature Check
- **Status**: Valid, Invalid, NotSigned
- **Risk**: Unsigned = HIGH
- **Check**: PowerShell Get-AuthenticodeSignature

### Entropy Analysis
- **Low (< 4.0)**: Uncompressed text
- **Medium (4-6)**: Normal executable
- **High (> 7.0)**: Packed/encrypted
- **Dangerous**: 7.5+ suggests packing

### API Import Analysis
Dangerous imports:
- `kernel32.dll::CreateRemoteThread` (code injection)
- `kernel32.dll::VirtualAllocEx` (memory manipulation)
- `ntdll.dll::ZwQuerySystemInformation` (privilege check)
- `wininet.dll::InternetOpen` (C2 communication)

---

## Credential Detection Patterns

### Password Strings
```regex
(?i)(password|pwd|passwd|pass)\s*[=:]\s*['"](.*)['""]
Examples:
  password = "SecurePass123"
  pwd = "MyPassword"
```

### API Keys
```regex
(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*['"](.*)['""]
Examples:
  api_key = "sk-abc123def456"
  APIKey = "xxxxxxxxxxxxxxxx"
```

### AWS Access Keys
```regex
AKIA[0-9A-Z]{16}
Examples:
  AKIAIOSFODNN7EXAMPLE
```

### Azure Storage Keys
```regex
DefaultEndpointsProtocol=https.*AccountKey=.*
Examples:
  DefaultEndpointsProtocol=https;AccountName=xxx;AccountKey=yyy==
```

### Private Keys
```regex
-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----
Examples:
  -----BEGIN RSA PRIVATE KEY-----
  -----BEGIN PRIVATE KEY-----
```

---

## Malware Indicators

### C2 Communication
```
Pattern: IP addresses (192.168.1.100)
Risk: Potential command & control
```

### Data Exfiltration
```
Pattern: steal, exfiltrate, encrypt.*files
Risk: Data theft indicators
```

### Process Injection
```
Pattern: CreateRemoteThread, VirtualAllocEx
Risk: Code injection capability
```

### Privilege Escalation
```
Pattern: SeDebugPrivilege, EnableLUA.*0
Risk: UAC bypass attempts
```

---

## Configuration Issues

### Weak Password Policy
```xml
MinPasswordLength = 4  ← Too short
PasswordComplexity = 0  ← No complexity
```

### Disabled Security
```xml
DisableDefender = true  ← Dangerous
DisableAV = true        ← Dangerous
```

### Excessive Logging
```xml
LogLevel = Debug  ← Too verbose
LogLevel = Trace  ← Performance impact
```

---

## CWE Reference

| CWE | Title | Severity |
|-----|-------|----------|
| CWE-798 | Hard-coded Credentials | CRITICAL |
| CWE-312 | Cleartext Storage | CRITICAL |
| CWE-95 | Code Injection | CRITICAL |
| CWE-648 | UAC Bypass | CRITICAL |
| CWE-200 | Information Exposure | HIGH |
| CWE-701 | Regex Issues | MEDIUM |
| CWE-656 | Packed Code | MEDIUM |

---

## MITRE ATT&CK Reference

| ID | Tactic | Technique | Risk |
|----|--------|-----------|------|
| T1086 | Execution | PowerShell | HIGH |
| T1105 | C2 | Remote File Copy | HIGH |
| T1112 | Defense Evasion | Modify Registry | HIGH |
| T1070 | Defense Evasion | Clear Logs | CRITICAL |
| T1088 | Privilege Escalation | Bypass UAC | CRITICAL |
| T1003 | Credential Access | Credential Dumping | CRITICAL |
| T1027 | Defense Evasion | Obfuscation | MEDIUM |

---

**Last Updated**: 2026-06-02
**Scanner Version**: 2.0 Enterprise
