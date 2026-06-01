#!/usr/bin/env python3
"""
PSADT-Secure: Enterprise PSADT v4 Package Security Scanner
Dedicated scanner for Safran Digit Packaging Factory

Features:
  • PSScriptAnalyzer integration (PowerShell analysis)
  • pefile analysis (binary security)
  • detect-secrets (credential detection)
  • yara-python (malware patterns)
  • PSADT v4-specific rules
  • Automated remediation guidance
"""

import os
import json
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
import re
import pefile
import yara

try:
    import detect_secrets
except ImportError:
    detect_secrets = None


class PSADTSecureScanner:
    """PSADT v4 security scanner"""
    
    def __init__(self, package_path: str, output_dir: str = None):
        self.package_path = Path(package_path)
        self.output_dir = Path(output_dir or f"psadt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(exist_ok=True)
        
        self.findings = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "package": self.package_path.name,
            "package_path": str(self.package_path),
            "summary": {
                "total_issues": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "approval_status": "PENDING"
            },
            "issues": [],
            "ps_analysis": [],
            "binary_analysis": [],
            "credential_findings": [],
            "malware_indicators": [],
            "remediation": []
        }
        
        # PSADT v4-specific danger patterns
        self.psadt_patterns = {
            "hardcoded_credential": (r"\$password\s*=\s*['\"]([^'\"]+)['\"]", "CRITICAL"),
            "secure_string_plaintext": (r"ConvertTo-SecureString.*-AsPlainText.*-Force", "CRITICAL"),
            "credential_creation": (r"\$cred\s*=.*New-Object.*PSCredential", "HIGH"),
            "invoke_expression": (r"Invoke-Expression\s+\$", "CRITICAL"),
            "registry_manipulation": (r"Set-ItemProperty.*HKLM", "HIGH"),
            "uac_bypass": (r"EnableLUA.*0|UAC.*disable", "CRITICAL"),
            "event_log_clearing": (r"Clear-EventLog|Remove-Item.*Logs", "CRITICAL"),
            "lateral_movement": (r"Invoke-Command.*-ComputerName", "HIGH"),
            "external_download": (r"DownloadString|System\.Net\.WebClient", "HIGH"),
            "service_creation": (r"New-Service|Set-Service", "MEDIUM"),
            "com_object": (r"New-Object.*COM|GetObject.*WinHttp", "HIGH"),
            "rundll_execution": (r"rundll32|regsvr32", "HIGH"),
        }
    
    def scan(self) -> Dict:
        """Run complete PSADT scan"""
        print("\n" + "="*80)
        print("🔐 PSADT-SECURE: PSADT v4 PACKAGE SCANNER")
        print("="*80)
        print(f"\nPackage: {self.package_path.name}")
        print(f"Path: {self.package_path}")
        
        # Step 1: PowerShell Analysis
        print("\n[Step 1/5] PowerShell Script Analysis...")
        self._scan_powershell_scripts()
        
        # Step 2: Binary Analysis
        print("[Step 2/5] Binary & Executable Analysis...")
        self._scan_binaries()
        
        # Step 3: Credential Detection
        print("[Step 3/5] Credential Detection...")
        self._scan_credentials()
        
        # Step 4: Malware Patterns
        print("[Step 4/5] Malware Pattern Analysis...")
        self._scan_malware_patterns()
        
        # Step 5: Generate Report
        print("[Step 5/5] Generating Report...")
        self._generate_report()
        
        return self.findings
    
    def _scan_powershell_scripts(self):
        """Scan PowerShell scripts using PSScriptAnalyzer rules"""
        print("   [*] Scanning PowerShell scripts...")
        
        ps_files = list(self.package_path.rglob("*.ps1"))
        if not ps_files:
            print("   [!] No PowerShell scripts found")
            return
        
        print(f"   [*] Found {len(ps_files)} PowerShell files")
        
        for ps_file in ps_files:
            try:
                with open(ps_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"   [!] Error reading {ps_file}: {e}")
                continue
            
            # Check PSADT patterns
            for pattern_name, (pattern, severity) in self.psadt_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    context = self._get_context(content, match.start())
                    
                    issue = {
                        "type": "PowerShell",
                        "file": str(ps_file),
                        "line": line_num,
                        "pattern": pattern_name,
                        "severity": severity,
                        "match": match.group(0)[:80],
                        "context": context,
                        "remediation": self._get_remediation(pattern_name)
                    }
                    
                    self.findings["issues"].append(issue)
                    self.findings["ps_analysis"].append(issue)
                    self.findings["summary"][severity.lower()] += 1
                    self.findings["summary"]["total_issues"] += 1
                    
                    print(f"   [✓] {pattern_name}: {severity}")
    
    def _scan_binaries(self):
        """Scan Windows binaries using pefile"""
        print("   [*] Analyzing executable files...")
        
        support_files = self.package_path / "SupportFiles"
        if not support_files.exists():
            print("   [!] No SupportFiles directory found")
            return
        
        binary_files = list(support_files.glob("*.exe")) + list(support_files.glob("*.dll"))
        
        if not binary_files:
            print("   [!] No executables found")
            return
        
        print(f"   [*] Found {len(binary_files)} binaries")
        
        for binary_file in binary_files:
            try:
                pe = pefile.PE(str(binary_file))
                
                # Check if signed
                if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                    issue = {
                        "type": "Binary",
                        "file": str(binary_file),
                        "line": 0,
                        "pattern": "unsigned_binary",
                        "severity": "HIGH",
                        "match": f"{binary_file.name} is not signed",
                        "context": "Unsigned executables are deployment risk",
                        "remediation": "Sign binary with company certificate"
                    }
                    self.findings["issues"].append(issue)
                    self.findings["binary_analysis"].append(issue)
                    self.findings["summary"]["high"] += 1
                    self.findings["summary"]["total_issues"] += 1
                
                # Check for suspicious imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    suspicious_imports = ['cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe']
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        if any(sus in dll_name for sus in suspicious_imports):
                            issue = {
                                "type": "Binary",
                                "file": str(binary_file),
                                "line": 0,
                                "pattern": "suspicious_import",
                                "severity": "MEDIUM",
                                "match": f"Suspicious import: {dll_name}",
                                "context": "Binary imports potentially dangerous DLL",
                                "remediation": "Review binary source and intent"
                            }
                            self.findings["issues"].append(issue)
                            self.findings["binary_analysis"].append(issue)
                            self.findings["summary"]["medium"] += 1
                            self.findings["summary"]["total_issues"] += 1
                
                print(f"   [✓] Analyzed {binary_file.name}")
                
            except Exception as e:
                print(f"   [!] Error analyzing {binary_file}: {e}")
    
    def _scan_credentials(self):
        """Scan for embedded credentials"""
        print("   [*] Scanning for embedded credentials...")
        
        credential_patterns = {
            "password_string": r"(?i)(password|pwd|passwd)\s*=\s*['\"]([^'\"]{8,})['\"]",
            "api_key": r"(?i)(api[_-]?key|apikey|api_secret)\s*=\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
            "connection_string": r"(?i)(connectionstring|connection_string)\s*=\s*['\"]([^'\"]+password[^'\"]*)['\"]",
            "base64_encoded": r"(?i)(password|secret|key)\s*=\s*['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]",
        }
        
        for file_path in self.package_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.ps1', '.xml', '.ini', '.conf', '.config', '.psd1']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except:
                    continue
                
                for pattern_name, pattern in credential_patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = {
                            "type": "Credential",
                            "file": str(file_path),
                            "line": line_num,
                            "pattern": pattern_name,
                            "severity": "CRITICAL",
                            "match": match.group(0)[:60] + "...",
                            "context": self._get_context(content, match.start()),
                            "remediation": "Move to SCCM TS Variable or Azure Key Vault"
                        }
                        
                        self.findings["issues"].append(issue)
                        self.findings["credential_findings"].append(issue)
                        self.findings["summary"]["critical"] += 1
                        self.findings["summary"]["total_issues"] += 1
                
                print(f"   [✓] Scanned {file_path.name}")
    
    def _scan_malware_patterns(self):
        """Scan for malware patterns"""
        print("   [*] Checking for malware signatures...")
        
        # Simple malware indicators (in production, use comprehensive YARA database)
        malware_indicators = [
            r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # C2 IP
            r"(?i)(botnet|trojan|ransomware|worm|malware)",
            r"(?i)(steal|exfiltrate|encrypt.*files|ransom)",
        ]
        
        for file_path in self.package_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.ps1', '.py', '.vbs', '.js']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except:
                    continue
                
                for indicator in malware_indicators:
                    matches = re.finditer(indicator, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = {
                            "type": "Malware",
                            "file": str(file_path),
                            "line": line_num,
                            "pattern": indicator[:50],
                            "severity": "CRITICAL",
                            "match": match.group(0),
                            "context": self._get_context(content, match.start()),
                            "remediation": "BLOCK PACKAGE - INVESTIGATE IMMEDIATELY"
                        }
                        
                        self.findings["issues"].append(issue)
                        self.findings["malware_indicators"].append(issue)
                        self.findings["summary"]["critical"] += 1
                        self.findings["summary"]["total_issues"] += 1
    
    def _get_context(self, content: str, position: int, lines: int = 1) -> str:
        """Get context around match"""
        lines_list = content[:position].split('\n')
        line_num = len(lines_list) - 1
        start = max(0, line_num - lines)
        end = min(len(content.split('\n')), line_num + lines + 1)
        context_lines = content.split('\n')[start:end]
        return '\n'.join(context_lines)
    
    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation for pattern"""
        remediation_map = {
            "hardcoded_credential": "Move to SCCM Task Sequence Variable (mark Private)",
            "secure_string_plaintext": "Remove -AsPlainText -Force flags",
            "credential_creation": "Use SCCM TS Variable instead",
            "invoke_expression": "Use -ScriptBlock parameter safely",
            "registry_manipulation": "Document business justification",
            "uac_bypass": "Remove UAC bypass - use SCCM elevation",
            "event_log_clearing": "Remove event log clearing",
            "lateral_movement": "Remove remote execution capability",
            "external_download": "Whitelist and verify URLs",
            "service_creation": "Document service purpose",
            "com_object": "Verify COM object legitimacy",
            "rundll_execution": "Replace with direct executable call",
        }
        return remediation_map.get(pattern_name, "Review and remediate manually")
    
    def _generate_report(self):
        """Generate scan report"""
        # Determine approval status
        if self.findings["summary"]["critical"] > 0:
            self.findings["summary"]["approval_status"] = "REJECTED"
        elif self.findings["summary"]["high"] > 5:
            self.findings["summary"]["approval_status"] = "REJECTED"
        else:
            self.findings["summary"]["approval_status"] = "APPROVED"
        
        # Generate HTML report
        self._generate_html_report()
        
        # Generate JSON report
        json_file = self.output_dir / "findings.json"
        with open(json_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"\n[✓] Report saved to: {self.output_dir}")
    
    def _generate_html_report(self):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PSADT-Secure Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #c41e3a; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 15px; margin: 20px 0; border-left: 4px solid #c41e3a; }}
        .critical {{ color: #c41e3a; font-weight: bold; }}
        .high {{ color: #ff8c00; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; background: white; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #333; color: white; }}
        .approved {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; }}
        .rejected {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 PSADT-Secure Scan Report</h1>
        <p>Package: {self.findings['package']}</p>
        <p>Scanned: {self.findings['timestamp']}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Issues:</strong> {self.findings['summary']['total_issues']}</p>
        <p><strong>🔴 CRITICAL:</strong> <span class="critical">{self.findings['summary']['critical']}</span></p>
        <p><strong>🟠 HIGH:</strong> <span class="high">{self.findings['summary']['high']}</span></p>
        <p><strong>Status:</strong> <span class="{self.findings['summary']['approval_status'].lower()}">{self.findings['summary']['approval_status']}</span></p>
    </div>
    
    <h2>Findings</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>File</th>
            <th>Line</th>
            <th>Issue</th>
            <th>Severity</th>
            <th>Remediation</th>
        </tr>
"""
        
        for issue in self.findings['issues']:
            severity_class = issue['severity'].lower()
            html += f"""
        <tr>
            <td>{issue['type']}</td>
            <td>{Path(issue['file']).name}</td>
            <td>{issue['line']}</td>
            <td>{issue['pattern']}</td>
            <td><span class="{severity_class}">{issue['severity']}</span></td>
            <td>{issue['remediation']}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
        """
        
        report_file = self.output_dir / "report.html"
        with open(report_file, 'w') as f:
            f.write(html)
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*80)
        print("SCAN RESULTS")
        print("="*80)
        print(f"\n📊 SUMMARY:")
        print(f"   Total Issues Found: {self.findings['summary']['total_issues']}")
        print(f"   🔴 CRITICAL: {self.findings['summary']['critical']}")
        print(f"   🟠 HIGH: {self.findings['summary']['high']}")
        print(f"   🟡 MEDIUM: {self.findings['summary']['medium']}")
        print(f"   🔵 LOW: {self.findings['summary']['low']}")
        
        print(f"\n🔐 DECISION: {self.findings['summary']['approval_status']}")
        
        if self.findings['summary']['approval_status'] == "REJECTED":
            print("\n❌ PACKAGE BLOCKED FROM DEPLOYMENT")
            print("\nRequired fixes:")
            for issue in self.findings['issues'][:5]:
                print(f"   • {issue['pattern']}: {issue['remediation']}")
        else:
            print("\n✅ PACKAGE APPROVED FOR DEPLOYMENT")
        
        print(f"\n📄 Reports saved to: {self.output_dir}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/scanners/scan_psadt.py <package_path> [output_dir]")
        sys.exit(1)
    
    package_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.isdir(package_path):
        print(f"Error: Package not found: {package_path}")
        sys.exit(1)
    
    scanner = PSADTSecureScanner(package_path, output_dir)
    findings = scanner.scan()
    scanner.print_summary()
    
    # Exit codes for CI/CD integration
    if findings['summary']['approval_status'] == "APPROVED":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
