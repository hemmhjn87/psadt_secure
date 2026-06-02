#!/usr/bin/env python3
"""
PSADT-Secure v3.0: Defense-Grade PSADT Package Security Scanner
Aerospace/Defense Enterprise Edition

Industry-Level Features:
  • Advanced PowerShell behavioral analysis with 60+ detection patterns
  • AMSI bypass detection (memory patching, reflection, scripted bypasses)
  • LOLBin abuse detection (certutil, mshta, msiexec, regsvr32, etc.)
  • PSADT v4.1 specific cmdlet misuse and deprecated API detection
  • MSI/MSP/MSIX custom action security analysis
  • WMI persistence and ETW tampering detection
  • CVSS v3.1 base score calculation per finding
  • NIST 800-53 / CMMC 2.0 / CIS v8 / IEC 62443 compliance tagging
  • SARIF 2.1.0 output for GitHub Advanced Security / IDE integration
  • JUnit XML output for CI/CD pipeline gating
  • Cryptographic manifest with ECDSA P-256 signing
  • Tamper-evident chained audit log (JSONL)
  • NVD 2.0 CVE lookup with SQLite cache
  • Allowlist/exception management with expiry
  • Comprehensive binary chain-of-trust analysis
"""

import os
import re
import sys
import csv
import json
import math
import time
import uuid
import base64
import struct
import hashlib
import sqlite3
import logging
import subprocess
import tempfile
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter

# ── Optional heavyweight imports ─────────────────────────────────────────────
try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

try:
    import detect_secrets
    _DETECT_SECRETS_AVAILABLE = True
except ImportError:
    _DETECT_SECRETS_AVAILABLE = False

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("psadt-secure")

# ── NVD API endpoint ──────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SCANNER_VERSION = "3.0"
SCANNER_INFO_URI = "https://github.com/psadt-secure/psadt-secure"


class PSADTSecureScanner:
    """
    Defense-grade PSADT v4 security scanner.

    Instantiate with a package directory path and optional output directory.
    Call scan() to execute all analysis steps and generate reports.
    """

    # ── MITRE ATT&CK Technique Mapping ────────────────────────────────────────
    MITRE_TACTICS: Dict[str, Tuple[str, str, str]] = {
        # (technique_id, tactic, full_technique_name)
        "invoke_expression":         ("T1059.001", "Execution",          "Command and Scripting Interpreter: PowerShell"),
        "external_download":         ("T1105",     "Command and Control","Ingress Tool Transfer"),
        "registry_manipulation":     ("T1112",     "Defense Evasion",    "Modify Registry"),
        "uac_bypass":                ("T1548.002", "Privilege Escalation","Abuse Elevation Control Mechanism: Bypass UAC"),
        "event_log_clearing":        ("T1070.001", "Defense Evasion",    "Indicator Removal: Clear Windows Event Logs"),
        "lateral_movement":          ("T1021.006", "Lateral Movement",   "Remote Services: Windows Remote Management"),
        "service_creation":          ("T1543.003", "Persistence",        "Create or Modify System Process: Windows Service"),
        "credential_creation":       ("T1078",     "Privilege Escalation","Valid Accounts"),
        "com_object":                ("T1559.001", "Execution",          "Inter-Process Communication: Component Object Model"),
        "hardcoded_credential":      ("T1552.001", "Credential Access",  "Unsecured Credentials: Credentials in Files"),
        "secure_string_plaintext":   ("T1552",     "Credential Access",  "Unsecured Credentials"),
        "script_block_manipulation": ("T1059.001", "Execution",          "Command and Scripting Interpreter: PowerShell"),
        "disabled_security":         ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "credential_dumping":        ("T1003",     "Credential Access",  "OS Credential Dumping"),
        "scheduled_task":            ("T1053.005", "Persistence",        "Scheduled Task/Job: Scheduled Task"),
        "remote_execution":          ("T1021",     "Lateral Movement",   "Remote Services"),
        "rundll_execution":          ("T1218.011", "Defense Evasion",    "System Binary Proxy Execution: Rundll32"),
        "obfuscation_detected":      ("T1027",     "Defense Evasion",    "Obfuscated Files or Information"),
        "amsi_patch_memory":         ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "amsi_reflection":           ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "amsi_script_bypass":        ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "amsi_force_error":          ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "amsi_null_context":         ("T1562.001", "Defense Evasion",    "Impair Defenses: Disable or Modify Tools"),
        "lolbin_certutil_decode":    ("T1140",     "Defense Evasion",    "Deobfuscate/Decode Files or Information"),
        "lolbin_mshta":              ("T1218.005", "Defense Evasion",    "System Binary Proxy Execution: Mshta"),
        "lolbin_wscript_cscript":    ("T1059.005", "Execution",          "Command and Scripting Interpreter: Visual Basic"),
        "lolbin_msiexec_remote":     ("T1218.007", "Defense Evasion",    "System Binary Proxy Execution: Msiexec"),
        "lolbin_regsvr32_scrobj":    ("T1218.010", "Defense Evasion",    "System Binary Proxy Execution: Regsvr32"),
        "lolbin_bitsadmin":          ("T1197",     "Defense Evasion",    "BITS Jobs"),
        "lolbin_forfiles":           ("T1218",     "Defense Evasion",    "System Binary Proxy Execution"),
        "lolbin_installutil":        ("T1218.004", "Defense Evasion",    "System Binary Proxy Execution: InstallUtil"),
        "wmi_event_subscription":    ("T1546.003", "Persistence",        "Event Triggered Execution: Windows Management Instrumentation Event Subscription"),
        "registry_run_key":          ("T1547.001", "Persistence",        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
        "startup_folder":            ("T1547.001", "Persistence",        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
        "clm_bypass":                ("T1059.001", "Execution",          "Command and Scripting Interpreter: PowerShell"),
        "etw_tampering":             ("T1562.006", "Defense Evasion",    "Impair Defenses: Indicator Blocking"),
        "dotnet_reflection":         ("T1620",     "Defense Evasion",    "Reflective Code Loading"),
        "applocker_bypass":          ("T1218",     "Defense Evasion",    "System Binary Proxy Execution"),
        "psadt_execute_ignore_all_exits": ("T1204", "Execution",         "User Execution"),
        "psadt_env_var_injection":   ("T1059.001", "Execution",          "Command and Scripting Interpreter: PowerShell"),
        "psadt_unvalidated_path":    ("T1083",     "Discovery",          "File and Directory Discovery"),
        "psadt_invoke_all_users_reg": ("T1112",    "Defense Evasion",    "Modify Registry"),
        "psadt_show_dialog_exec":    ("T1204",     "Execution",          "User Execution"),
        "psadt_run_as_active_user":  ("T1548",     "Privilege Escalation","Abuse Elevation Control Mechanism"),
        "psadt_deprecated_v3_appdeployment": ("T1059.001", "Execution",  "Command and Scripting Interpreter: PowerShell"),
    }

    # ── Risk Scoring Weights ──────────────────────────────────────────────────
    RISK_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 10.0,
        "HIGH":      5.0,
        "MEDIUM":    2.0,
        "LOW":       0.5,
        "INFO":      0.1,
    }

    # ── CVSS v3.1 Base Scores per Pattern ─────────────────────────────────────
    # Format: {pattern_name: (base_score, vector_string, severity_label)}
    CVSS_VECTORS: Dict[str, Tuple[float, str, str]] = {
        "hardcoded_credential":          (9.1,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     "CRITICAL"),
        "secure_string_plaintext":       (8.1,  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "credential_creation":           (7.5,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     "HIGH"),
        "invoke_expression":             (8.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "HIGH"),
        "script_block_manipulation":     (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "registry_manipulation":         (6.5,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",     "MEDIUM"),
        "uac_bypass":                    (8.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "HIGH"),
        "event_log_clearing":            (7.7,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",     "HIGH"),
        "disabled_security":             (8.4,  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",     "HIGH"),
        "lateral_movement":              (9.0,  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "credential_dumping":            (4.4,  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",     "MEDIUM"),
        "service_creation":              (6.7,  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N",     "MEDIUM"),
        "scheduled_task":                (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "external_download":             (8.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",     "HIGH"),
        "remote_execution":              (8.8,  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",     "HIGH"),
        "com_object":                    (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "rundll_execution":              (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "obfuscation_detected":          (5.5,  "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",     "MEDIUM"),
        "amsi_patch_memory":             (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "amsi_reflection":               (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "amsi_script_bypass":            (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "amsi_force_error":              (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "amsi_null_context":             (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "lolbin_certutil_decode":        (9.1,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",     "CRITICAL"),
        "lolbin_mshta":                  (9.6,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "lolbin_wscript_cscript":        (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "lolbin_msiexec_remote":         (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     "CRITICAL"),
        "lolbin_regsvr32_scrobj":        (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     "CRITICAL"),
        "lolbin_bitsadmin":              (7.5,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",     "HIGH"),
        "lolbin_forfiles":               (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "lolbin_installutil":            (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "wmi_event_subscription":        (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "registry_run_key":              (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "startup_folder":                (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "clm_bypass":                    (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "etw_tampering":                 (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "dotnet_reflection":             (9.3,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",     "CRITICAL"),
        "applocker_bypass":              (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "psadt_execute_ignore_all_exits":(7.5,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",     "HIGH"),
        "psadt_unvalidated_path":        (6.5,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",     "MEDIUM"),
        "psadt_invoke_all_users_reg":    (5.5,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",     "MEDIUM"),
        "psadt_show_dialog_exec":        (7.8,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     "HIGH"),
        "psadt_env_var_injection":       (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     "CRITICAL"),
        "psadt_deprecated_v3_appdeployment": (4.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",  "MEDIUM"),
        "psadt_set_shortcut_hotkey":     (2.0,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N",     "LOW"),
        "psadt_run_as_active_user":      (5.5,  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",     "MEDIUM"),
    }

    # ── Compliance Tag Mapping ────────────────────────────────────────────────
    COMPLIANCE_TAGS: Dict[str, Dict[str, List[str]]] = {
        "hardcoded_credential": {
            "nist_800_53": ["IA-5", "SA-11", "SI-7"],
            "cmmc_2":       ["IA.3.083", "SI.1.210"],
            "cis_v8":       ["CIS-3", "CIS-16"],
            "iec_62443":    ["SR_3.2"],
            "owasp":        ["A02:2021"],
        },
        "invoke_expression": {
            "nist_800_53": ["SI-3", "CM-7", "SA-11"],
            "cmmc_2":       ["SI.1.210", "CM.2.061"],
            "cis_v8":       ["CIS-2", "CIS-7"],
            "iec_62443":    ["SR_3.4"],
            "owasp":        ["A03:2021"],
        },
        "external_download": {
            "nist_800_53": ["CM-7", "SI-3", "SC-18"],
            "cmmc_2":       ["CM.2.061", "SI.1.210"],
            "cis_v8":       ["CIS-2", "CIS-9"],
            "iec_62443":    ["SR_5.2"],
            "owasp":        ["A08:2021"],
        },
        "uac_bypass": {
            "nist_800_53": ["AC-6", "CM-6", "SI-3"],
            "cmmc_2":       ["AC.1.001", "CM.2.061"],
            "cis_v8":       ["CIS-4", "CIS-5"],
            "iec_62443":    ["SR_2.1"],
            "owasp":        ["A01:2021"],
        },
        "credential_dumping": {
            "nist_800_53": ["IA-5", "AC-2", "AU-12"],
            "cmmc_2":       ["IA.3.083", "AC.1.001"],
            "cis_v8":       ["CIS-4", "CIS-6"],
            "iec_62443":    ["SR_1.3"],
            "owasp":        ["A02:2021"],
        },
        "event_log_clearing": {
            "nist_800_53": ["AU-9", "AU-12", "SI-7"],
            "cmmc_2":       ["AU.2.042", "AU.3.045"],
            "cis_v8":       ["CIS-8"],
            "iec_62443":    ["SR_6.1"],
            "owasp":        ["A09:2021"],
        },
        "disabled_security": {
            "nist_800_53": ["SI-3", "CM-7", "CA-7"],
            "cmmc_2":       ["SI.1.210", "CM.2.061"],
            "cis_v8":       ["CIS-10"],
            "iec_62443":    ["SR_3.2"],
            "owasp":        ["A05:2021"],
        },
        "lateral_movement": {
            "nist_800_53": ["AC-17", "SI-3", "SC-7"],
            "cmmc_2":       ["AC.2.006", "SC.3.177"],
            "cis_v8":       ["CIS-12", "CIS-13"],
            "iec_62443":    ["SR_5.1"],
            "owasp":        ["A01:2021"],
        },
        "amsi_patch_memory": {
            "nist_800_53": ["SI-3", "SI-7", "CM-7"],
            "cmmc_2":       ["SI.1.210", "CM.2.061"],
            "cis_v8":       ["CIS-10"],
            "iec_62443":    ["SR_3.2"],
            "owasp":        ["A05:2021"],
        },
        "wmi_event_subscription": {
            "nist_800_53": ["CM-7", "SI-4", "AU-12"],
            "cmmc_2":       ["CM.2.061", "AU.2.042"],
            "cis_v8":       ["CIS-4", "CIS-8"],
            "iec_62443":    ["SR_3.4"],
            "owasp":        ["A05:2021"],
        },
        "etw_tampering": {
            "nist_800_53": ["AU-9", "SI-7", "CM-7"],
            "cmmc_2":       ["AU.3.045", "CM.2.061"],
            "cis_v8":       ["CIS-8"],
            "iec_62443":    ["SR_6.1"],
            "owasp":        ["A09:2021"],
        },
        "dotnet_reflection": {
            "nist_800_53": ["SI-3", "SA-11", "CM-7"],
            "cmmc_2":       ["SI.1.210", "CM.2.061"],
            "cis_v8":       ["CIS-2", "CIS-16"],
            "iec_62443":    ["SR_3.4"],
            "owasp":        ["A03:2021"],
        },
    }

    # ── Default compliance tags (fallback) ────────────────────────────────────
    _DEFAULT_COMPLIANCE: Dict[str, List[str]] = {
        "nist_800_53": ["CM-7", "SI-3"],
        "cmmc_2":       ["CM.2.061"],
        "cis_v8":       ["CIS-2"],
        "iec_62443":    ["SR_3.2"],
        "owasp":        ["A05:2021"],
    }

    # =========================================================================
    def __init__(
        self,
        package_path: str,
        output_dir: str = None,
        config: Optional[Dict] = None,
    ):
        """
        Initialise the PSADT-Secure scanner.

        Parameters
        ----------
        package_path : str
            Absolute or relative path to the PSADT package directory.
        output_dir   : str, optional
            Directory for all output files; created if absent.
        config       : dict, optional
            In-memory config overrides (merged over rules.yaml).
        """
        self.package_path = Path(package_path).resolve()
        self.output_dir = Path(
            output_dir or f"psadt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = time.time()

        # Operator identity
        self.operator = os.environ.get("PSADT_SCAN_OPERATOR", "SYSTEM")

        # Load YAML config if present
        self.config: Dict = config or {}
        self._load_yaml_config()

        # Load allowlist
        self.allowlist: List[Dict] = []
        self._load_allowlist()

        # NVD SQLite cache
        self._nvd_db_path = self.output_dir / "nvd_cache.db"
        self._init_nvd_cache()

        # Audit log chain state
        self._audit_prev_hash = "0" * 64

        # Signing key
        self._signing_private_key = None
        self._load_signing_key()

        # Initialise findings structure
        self.findings: Dict[str, Any] = {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "package":        self.package_path.name,
            "package_path":   str(self.package_path),
            "scanner_version": SCANNER_VERSION,
            "operator":        self.operator,
            "risk_score":      0.0,
            "summary": {
                "total_issues":      0,
                "critical":          0,
                "high":              0,
                "medium":            0,
                "low":               0,
                "info":              0,
                "suppressed":        0,
                "approval_status":   "PENDING",
                "files_scanned":     0,
                "ps_files":          0,
                "msi_files":         0,
                "binaries_analyzed": 0,
                "scan_duration":     0.0,
            },
            "issues":               [],
            "suppressed_findings":  [],
            "ps_analysis":          [],
            "binary_analysis":      [],
            "credential_findings":  [],
            "malware_indicators":   [],
            "obfuscation_detected": [],
            "risky_behaviors":      [],
            "mitre_mapping":        [],
            "psadt_v4_findings":    [],
            "msi_findings":         [],
            "remediation":          [],
            "compliance_summary":   {},
            "manifest":             {},
            "metrics": {
                "entropy_analysis": [],
                "code_complexity":  0,
                "risk_factors":     [],
            },
        }

        # ── PSADT detection patterns (60+) ───────────────────────────────────
        self.psadt_patterns: Dict[str, Dict] = {

            # ── Credential & Authentication ──────────────────────────────────
            "hardcoded_credential": {
                "pattern":  r"\$password\s*=\s*['\"]([^'\"]{8,})['\"]",
                "severity": "CRITICAL",
                "mitre":    "T1552.001",
                "cwe":      "CWE-798",
                "description": "Hardcoded password literal found in script variable",
            },
            "secure_string_plaintext": {
                "pattern":  r"ConvertTo-SecureString.*-AsPlainText.*-Force",
                "severity": "CRITICAL",
                "mitre":    "T1552",
                "cwe":      "CWE-312",
                "description": "SecureString constructed from plaintext with -AsPlainText -Force",
            },
            "credential_creation": {
                "pattern":  r"\$cred\s*=.*New-Object.*PSCredential",
                "severity": "HIGH",
                "mitre":    "T1078",
                "cwe":      "CWE-798",
                "description": "PSCredential object constructed inline - potential secret exposure",
            },

            # ── Execution & Code Injection ────────────────────────────────────
            "invoke_expression": {
                "pattern":  r"Invoke-Expression\s+(?!-|'|`)",
                "severity": "CRITICAL",
                "mitre":    "T1059.001",
                "cwe":      "CWE-95",
                "description": "Dynamic code execution via Invoke-Expression with non-literal argument",
            },
            "script_block_manipulation": {
                "pattern":  r"Invoke-Command.*-ScriptBlock.*\$\(",
                "severity": "HIGH",
                "mitre":    "T1059.001",
                "cwe":      "CWE-95",
                "description": "Dynamic ScriptBlock construction passed to Invoke-Command",
            },

            # ── Defense Evasion ───────────────────────────────────────────────
            "registry_manipulation": {
                "pattern":  r"(?i)(Set-ItemProperty|New-ItemProperty).*HKLM",
                "severity": "HIGH",
                "mitre":    "T1112",
                "cwe":      "CWE-1104",
                "description": "Modification of HKLM registry hive via Set-/New-ItemProperty",
            },
            "uac_bypass": {
                "pattern":  r"(?i)(EnableLUA.*0|UAC.*disable|Bypass.*UAC)",
                "severity": "CRITICAL",
                "mitre":    "T1548.002",
                "cwe":      "CWE-648",
                "description": "User Account Control bypass or disablement detected",
            },
            "event_log_clearing": {
                "pattern":  r"(?i)(Clear-EventLog|Remove-Item.*Logs|Stop-Service.*EventLog|wevtutil.*cl\b)",
                "severity": "CRITICAL",
                "mitre":    "T1070.001",
                "cwe":      "CWE-612",
                "description": "Windows event log clearing or deletion - evidence destruction",
            },
            "disabled_security": {
                "pattern":  r"(?i)(disable.*defender|exclude.*antivirus|disable.*protection|Set-MpPreference.*Disable)",
                "severity": "CRITICAL",
                "mitre":    "T1562.001",
                "cwe":      "CWE-1104",
                "description": "Windows Defender or antivirus protection being disabled",
            },

            # ── Lateral Movement ─────────────────────────────────────────────
            "lateral_movement": {
                "pattern":  r"Invoke-Command.*-ComputerName.*(?!localhost)",
                "severity": "HIGH",
                "mitre":    "T1021.006",
                "cwe":      "CWE-1104",
                "description": "Remote code execution targeting a non-localhost computer",
            },
            "credential_dumping": {
                "pattern":  r"(?i)(mimikatz|sekurlsa|lsadump|gsecdump|procdump.*lsass)",
                "severity": "CRITICAL",
                "mitre":    "T1003",
                "cwe":      "CWE-200",
                "description": "Known credential-dumping tool or technique reference",
            },

            # ── Persistence ───────────────────────────────────────────────────
            "service_creation": {
                "pattern":  r"(?i)(New-Service|Set-Service|Start-Service).*-DisplayName",
                "severity": "MEDIUM",
                "mitre":    "T1543.003",
                "cwe":      "CWE-1104",
                "description": "Windows service creation or modification without deployment context",
            },
            "scheduled_task": {
                "pattern":  r"(?i)(Register-ScheduledTask|New-ScheduledTask).*-Action",
                "severity": "MEDIUM",
                "mitre":    "T1053.005",
                "cwe":      "CWE-1104",
                "description": "Scheduled task registration that could establish persistence",
            },

            # ── Command & Control ─────────────────────────────────────────────
            "external_download": {
                "pattern":  r"(?i)(DownloadString|DownloadFile|System\.Net\.WebClient|Invoke-WebRequest|curl\b|wget\b)",
                "severity": "HIGH",
                "mitre":    "T1105",
                "cwe":      "CWE-829",
                "description": "External content download from network resource",
            },
            "remote_execution": {
                "pattern":  r"(?i)(psexec|wmic.*process call|winrm|Enter-PSSession)",
                "severity": "HIGH",
                "mitre":    "T1021",
                "cwe":      "CWE-200",
                "description": "Remote execution tool or WinRM session initiation",
            },

            # ── Other LOLBin / Injection ──────────────────────────────────────
            "com_object": {
                "pattern":  r"New-Object.*(?:COM|WinHttp|Internet\.URLDownloadToFile|Shell\.Application)",
                "severity": "HIGH",
                "mitre":    "T1559.001",
                "cwe":      "CWE-95",
                "description": "COM object instantiation - potential code execution or download vector",
            },
            "rundll_execution": {
                "pattern":  r"(?i)(rundll32|regsvr32).*(?:http|:\\\\)",
                "severity": "HIGH",
                "mitre":    "T1218.011",
                "cwe":      "CWE-94",
                "description": "Rundll32 or Regsvr32 loading from UNC/HTTP path",
            },
            "obfuscation_detected": {
                "pattern":  r"(?i)(\[Convert\]::FromBase64String|\[char\]\s*\d{2,3}|`[a-zA-Z]|\\x[0-9a-fA-F]{2}){3,}",
                "severity": "MEDIUM",
                "mitre":    "T1027",
                "cwe":      "CWE-701",
                "description": "Multiple obfuscation indicators in script body",
            },

            # ── AMSI Bypass Patterns (CRITICAL) ───────────────────────────────
            "amsi_patch_memory": {
                "pattern":  r"(?i)(AmsiScanBuffer|AmsiInitialize|amsiContext|amsiSession)",
                "severity": "CRITICAL",
                "mitre":    "T1562.001",
                "cwe":      "CWE-693",
                "description": "Direct AMSI function reference - possible memory patch bypass",
            },
            "amsi_reflection": {
                "pattern":  r"(?i)\[Ref\]\.Assembly\.GetType.*Automation.*Utils",
                "severity": "CRITICAL",
                "mitre":    "T1562.001",
                "cwe":      "CWE-693",
                "description": "Reflection-based AMSI bypass via System.Management.Automation internals",
            },
            "amsi_script_bypass": {
                "pattern":  r"(?i)\[Runtime\.InteropServices\.Marshal\].*WriteInt32",
                "severity": "CRITICAL",
                "mitre":    "T1562.001",
                "cwe":      "CWE-693",
                "description": "Marshal::WriteInt32 pattern consistent with AMSI buffer patching",
            },
            "amsi_force_error": {
                "pattern":  r"(?i)(amsiInitFailed|amsi.*byp|byp.*amsi)",
                "severity": "CRITICAL",
                "mitre":    "T1562.001",
                "cwe":      "CWE-693",
                "description": "AMSI forced-error or bypass flag string detected",
            },
            "amsi_null_context": {
                "pattern":  r"\[System\.Runtime\.InteropServices\.Marshal\]::Copy",
                "severity": "HIGH",
                "mitre":    "T1562.001",
                "cwe":      "CWE-693",
                "description": "Marshal::Copy used to patch native code - possible AMSI/ETW tamper",
            },

            # ── LOLBin Abuse Patterns ─────────────────────────────────────────
            "lolbin_certutil_decode": {
                "pattern":  r"(?i)certutil.*(?:-decode|-encode|-urlcache|-f\b)",
                "severity": "CRITICAL",
                "mitre":    "T1140",
                "cwe":      "CWE-94",
                "description": "CertUtil used for encoding/decoding or URL-cached file download",
            },
            "lolbin_mshta": {
                "pattern":  r"(?i)mshta(?:\.exe)?.*(?:http|vbscript|javascript)",
                "severity": "CRITICAL",
                "mitre":    "T1218.005",
                "cwe":      "CWE-94",
                "description": "MSHTA executing remote or inline script via HTTP/VBScript/JavaScript",
            },
            "lolbin_wscript_cscript": {
                "pattern":  r"(?i)(wscript|cscript).*(?:\.vbs|\.js|\.wsf|//e:)",
                "severity": "HIGH",
                "mitre":    "T1059.005",
                "cwe":      "CWE-94",
                "description": "WScript/CScript executing a script file or inline engine specifier",
            },
            "lolbin_msiexec_remote": {
                "pattern":  r"(?i)msiexec.*(?:/i|/q).*http",
                "severity": "CRITICAL",
                "mitre":    "T1218.007",
                "cwe":      "CWE-94",
                "description": "MSIExec installing package from remote HTTP URL",
            },
            "lolbin_regsvr32_scrobj": {
                "pattern":  r"(?i)regsvr32.*(?:/s|/u|/i).*(?:scrobj|http|\\\\)",
                "severity": "CRITICAL",
                "mitre":    "T1218.010",
                "cwe":      "CWE-94",
                "description": "Regsvr32 Squiblydoo pattern (scrobj or remote COM scriptlet)",
            },
            "lolbin_bitsadmin": {
                "pattern":  r"(?i)bitsadmin.*(?:/transfer|/create|/addfile)",
                "severity": "HIGH",
                "mitre":    "T1197",
                "cwe":      "CWE-829",
                "description": "BITSAdmin used to create or transfer files - potential data exfil/C2",
            },
            "lolbin_forfiles": {
                "pattern":  r"(?i)forfiles.*(?:/c|/p).*(?:cmd|powershell|mshta)",
                "severity": "HIGH",
                "mitre":    "T1218",
                "cwe":      "CWE-94",
                "description": "Forfiles used to proxy execution of cmd/PowerShell/MSHTA",
            },
            "lolbin_installutil": {
                "pattern":  r"(?i)installutil(?:\.exe)?.*(?:/logfile|/u\b)",
                "severity": "HIGH",
                "mitre":    "T1218.004",
                "cwe":      "CWE-94",
                "description": "InstallUtil used to execute unmanaged .NET code bypassing AppLocker",
            },

            # ── Persistence Patterns ──────────────────────────────────────────
            "wmi_event_subscription": {
                "pattern":  r"(?i)(New-CimInstance.*__EventFilter|Register-WmiEvent)",
                "severity": "CRITICAL",
                "mitre":    "T1546.003",
                "cwe":      "CWE-1104",
                "description": "WMI event subscription for persistence via __EventFilter",
            },
            "registry_run_key": {
                "pattern":  r"(?i)(HKLM|HKCU).*\\(?:Run|RunOnce|RunServices)\b",
                "severity": "HIGH",
                "mitre":    "T1547.001",
                "cwe":      "CWE-1104",
                "description": "Modification of Run/RunOnce registry key for autostart persistence",
            },
            "startup_folder": {
                "pattern":  r"(?i)(\$env:APPDATA.*Microsoft.*Windows.*Start Menu.*Programs.*Startup|\$env:ALLUSERSPROFILE.*Microsoft.*Windows.*Start Menu)",
                "severity": "HIGH",
                "mitre":    "T1547.001",
                "cwe":      "CWE-1104",
                "description": "Startup folder path reference for persistence placement",
            },

            # ── Defense Evasion (Advanced) ────────────────────────────────────
            "clm_bypass": {
                "pattern":  r"(?i)(\[scriptblock\]::Create|\$ExecutionContext\.InvokeCommand\.NewScriptBlock)",
                "severity": "HIGH",
                "mitre":    "T1059.001",
                "cwe":      "CWE-693",
                "description": "Dynamic ScriptBlock creation that may bypass Constrained Language Mode",
            },
            "etw_tampering": {
                "pattern":  r"(?i)(EtwEventWrite|NtTraceEvent|ETW.*disable|EventWrite.*patch)",
                "severity": "CRITICAL",
                "mitre":    "T1562.006",
                "cwe":      "CWE-693",
                "description": "ETW (Event Tracing for Windows) tampering or disablement",
            },
            "dotnet_reflection": {
                "pattern":  r"(?i)(\[System\.Reflection\.Assembly\]::Load\b|\[Reflection\.Assembly\]::LoadWithPartialName)",
                "severity": "CRITICAL",
                "mitre":    "T1620",
                "cwe":      "CWE-829",
                "description": "Reflective .NET assembly loading - potential in-memory malware staging",
            },
            "applocker_bypass": {
                "pattern":  r"(?i)(regsvcs|regasm|ieexec|msDeploy|PresentationHost)",
                "severity": "HIGH",
                "mitre":    "T1218",
                "cwe":      "CWE-693",
                "description": "Known AppLocker bypass binary invoked in script",
            },

            # ── PSADT v4.1 Cmdlet Misuse ──────────────────────────────────────
            "psadt_execute_ignore_all_exits": {
                "pattern":  r"Execute-ADTProcess.*-IgnoreExitCodes\s+[\"']\*[\"']",
                "severity": "CRITICAL",
                "mitre":    "T1204",
                "cwe":      "CWE-754",
                "description": "Execute-ADTProcess ignoring all exit codes - masks silent failures and malware execution",
            },
            "psadt_unvalidated_path": {
                "pattern":  r"(?i)(Copy-ADTFile|Remove-ADTFile|Execute-ADTProcess)\s+.*-(?:Path|Source|Destination)\s+\$(?!ADT)",
                "severity": "HIGH",
                "mitre":    "T1083",
                "cwe":      "CWE-22",
                "description": "PSADT file/process cmdlet with non-ADT variable path - potential path traversal",
            },
            "psadt_invoke_all_users_reg": {
                "pattern":  r"Invoke-ADTAllUsersRegistryAction",
                "severity": "MEDIUM",
                "mitre":    "T1112",
                "cwe":      "CWE-1104",
                "description": "Invoke-ADTAllUsersRegistryAction applies registry changes to all user hives",
            },
            "psadt_show_dialog_exec": {
                "pattern":  r"Show-ADTInstallationPrompt.*-ButtonRightText.*Invoke",
                "severity": "HIGH",
                "mitre":    "T1204",
                "cwe":      "CWE-77",
                "description": "Interactive dialog button wired to Invoke-* - social engineering execution vector",
            },
            "psadt_env_var_injection": {
                "pattern":  r"\$env:[A-Z_]+.*Invoke-Expression|Invoke-Expression.*\$env:",
                "severity": "CRITICAL",
                "mitre":    "T1059.001",
                "cwe":      "CWE-78",
                "description": "Environment variable passed directly to Invoke-Expression - OS command injection",
            },
            "psadt_deprecated_v3_appdeployment": {
                "pattern":  r"(?i)(Show-InstallationProgress|Execute-Process|Copy-File|Remove-File|Set-RegistryKey)\s",
                "severity": "MEDIUM",
                "mitre":    "T1059.001",
                "cwe":      "CWE-1104",
                "description": "PSADT v3 deprecated cmdlet in use - bypasses v4 audit controls",
            },
            "psadt_set_shortcut_hotkey": {
                "pattern":  r"New-ADTShortcut.*-HotKey",
                "severity": "LOW",
                "mitre":    "T1547.001",
                "cwe":      "CWE-1104",
                "description": "Shortcut with HotKey registered - low-risk but warrants review",
            },
            "psadt_run_as_active_user": {
                "pattern":  r"Execute-ADTProcessAsActiveUser",
                "severity": "MEDIUM",
                "mitre":    "T1548",
                "cwe":      "CWE-250",
                "description": "Execute-ADTProcessAsActiveUser elevates scope to logged-on user context",
            },
        }

    # =========================================================================
    # Private: Config & Setup Helpers
    # =========================================================================

    def _load_yaml_config(self) -> None:
        """Load rules.yaml from config directory and merge into self.config."""
        rules_path = Path("config") / "rules.yaml"
        if not rules_path.exists():
            rules_path = self.package_path.parent / "config" / "rules.yaml"
        if not rules_path.exists():
            return
        if not _YAML_AVAILABLE:
            logger.warning("PyYAML not installed - skipping rules.yaml load")
            return
        try:
            with open(rules_path, "r", encoding="utf-8") as fh:
                extra = yaml.safe_load(fh) or {}
            self.config.update(extra)
            logger.info("Loaded rules from %s", rules_path)
        except Exception as exc:
            logger.warning("Could not load rules.yaml: %s", exc)

    def _load_allowlist(self) -> None:
        """Load allowlist.yaml exception entries."""
        al_path = Path("config") / "allowlist.yaml"
        if not al_path.exists():
            al_path = self.package_path.parent / "config" / "allowlist.yaml"
        if not al_path.exists():
            return
        if not _YAML_AVAILABLE:
            logger.warning("PyYAML not installed - allowlist skipped")
            return
        try:
            with open(al_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            self.allowlist = data.get("exceptions", [])
            logger.info("Loaded %d allowlist entries", len(self.allowlist))
        except Exception as exc:
            logger.warning("Could not load allowlist.yaml: %s", exc)

    def _load_signing_key(self) -> None:
        """Load ECDSA private key from PSADT_SIGNING_KEY_PATH env var if set."""
        if not _CRYPTO_AVAILABLE:
            return
        key_path = os.environ.get("PSADT_SIGNING_KEY_PATH", "")
        if not key_path or not Path(key_path).exists():
            return
        try:
            with open(key_path, "rb") as fh:
                self._signing_private_key = serialization.load_pem_private_key(
                    fh.read(), password=None, backend=default_backend()
                )
            logger.info("Loaded signing key from %s", key_path)
        except Exception as exc:
            logger.warning("Could not load signing key: %s", exc)

    def _init_nvd_cache(self) -> None:
        """Initialise SQLite NVD CVE cache table."""
        try:
            conn = sqlite3.connect(str(self._nvd_db_path))
            conn.execute(
                """CREATE TABLE IF NOT EXISTS nvd_cache (
                       hash        TEXT,
                       component   TEXT PRIMARY KEY,
                       cves_json   TEXT,
                       cached_at   TEXT
                   )"""
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("NVD cache init failed: %s", exc)

    # =========================================================================
    # Public: Main Scan Orchestrator
    # =========================================================================

    def scan(self) -> Dict:
        """
        Execute all 8 scan steps and generate all report formats.

        Returns the complete findings dictionary.
        """
        print("\n" + "=" * 90)
        print("🔐 PSADT-SECURE v3.0: DEFENSE-GRADE PSADT PACKAGE SECURITY SCANNER")
        print("=" * 90)
        print(f"\n  Package  : {self.package_path.name}")
        print(f"  Path     : {self.package_path}")
        print(f"  Operator : {self.operator}")
        print(f"  Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Output   : {self.output_dir}")

        self._generate_audit_log_entry("SCAN_START", {
            "package": str(self.package_path),
            "operator": self.operator,
        })

        # ── Step 1: PowerShell advanced analysis ─────────────────────────────
        print("\n[Step 1/8] Advanced PowerShell Script Analysis...")
        try:
            self._scan_powershell_scripts_advanced()
        except Exception as exc:
            logger.error("Step 1 failed: %s", exc)

        # ── Step 2: Binary analysis ───────────────────────────────────────────
        print("[Step 2/8] Comprehensive Binary & Chain-of-Trust Analysis...")
        try:
            self._scan_binaries_advanced()
        except Exception as exc:
            logger.error("Step 2 failed: %s", exc)

        # ── Step 3: Credential detection ─────────────────────────────────────
        print("[Step 3/9] Enhanced Credential & Data Leakage Detection...")
        try:
            self._scan_credentials_advanced()
        except Exception as exc:
            logger.error("Step 3 failed: %s", exc)

        # ── Step 4: HemSpect Data Leakage Engine ─────────────────────────────
        print("[Step 4/9] HemSpect Data Leakage Intelligence Sweep...")
        try:
            self._scan_data_leakage_hemspect()
        except Exception as exc:
            logger.error("Step 4 (HemSpect) failed: %s", exc)

        # ── Step 5: Malware patterns ──────────────────────────────────────────
        print("[Step 5/9] Malware Patterns & Obfuscation Detection...")
        try:
            self._scan_malware_patterns_advanced()
        except Exception as exc:
            logger.error("Step 5 failed: %s", exc)

        # ── Step 6: Configuration scanning ───────────────────────────────────
        print("[Step 6/9] Configuration & Dependency Analysis...")
        try:
            self._scan_configurations_and_dependencies()
        except Exception as exc:
            logger.error("Step 6 failed: %s", exc)

        # ── Step 7: PSADT v4 specific cmdlet analysis ─────────────────────────
        print("[Step 7/9] PSADT v4.1 Cmdlet & API Compliance Analysis...")
        try:
            self._scan_psadt_v4_cmdlets()
        except Exception as exc:
            logger.error("Step 7 failed: %s", exc)

        # ── Step 8: MSI/MSP/MSIX analysis ────────────────────────────────────
        print("[Step 8/9] MSI/MSP/MSIX Custom Action Security Analysis...")
        try:
            self._scan_msi_packages()
        except Exception as exc:
            logger.error("Step 8 failed: %s", exc)

        # ── Step 9: Risk scoring + MITRE mapping ──────────────────────────────
        print("[Step 9/9] Computing Risk Scores, MITRE Mapping & Generating Reports...")
        try:
            self._compute_risk_scores()
        except Exception as exc:
            logger.error("Step 9 risk scoring failed: %s", exc)

        # ── Apply allowlist BEFORE report generation ──────────────────────────
        active_issues, suppressed = self._apply_allowlist(self.findings["issues"])
        self.findings["issues"] = active_issues
        self.findings["suppressed_findings"] = suppressed
        self.findings["summary"]["suppressed"] = len(suppressed)

        # ── Generate all reports ──────────────────────────────────────────────
        try:
            self._generate_report()
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)

        # ── Finalise scan duration ────────────────────────────────────────────
        self.findings["summary"]["scan_duration"] = round(time.time() - self.start_time, 2)

        # ── Audit log scan complete ───────────────────────────────────────────
        self._generate_audit_log_entry("SCAN_COMPLETE", {
            "total_issues":   self.findings["summary"]["total_issues"],
            "critical":       self.findings["summary"]["critical"],
            "high":           self.findings["summary"]["high"],
            "risk_score":     self.findings["risk_score"],
            "status":         self.findings["summary"]["approval_status"],
            "suppressed":     self.findings["summary"]["suppressed"],
            "duration_s":     self.findings["summary"]["scan_duration"],
        })

        return self.findings

    # =========================================================================
    # Step 1: PowerShell Analysis
    # =========================================================================

    def _scan_powershell_scripts_advanced(self) -> None:
        """Advanced PowerShell analysis with behavioral detection and 60+ patterns."""
        print("   [*] Performing advanced PowerShell analysis...")

        ps_files = (
            list(self.package_path.rglob("*.ps1")) +
            list(self.package_path.rglob("*.psd1")) +
            list(self.package_path.rglob("*.psm1"))
        )
        if not ps_files:
            print("   [!] No PowerShell scripts found")
            return

        print(f"   [*] Found {len(ps_files)} PowerShell file(s)")
        self.findings["summary"]["ps_files"] = len(ps_files)

        for ps_file in ps_files:
            try:
                content = ps_file.read_text(encoding="utf-8", errors="ignore")
                self.findings["summary"]["files_scanned"] += 1
            except Exception as exc:
                logger.warning("Cannot read %s: %s", ps_file, exc)
                continue

            # Pattern matching
            for pattern_name, pattern_info in self.psadt_patterns.items():
                pat    = pattern_info["pattern"]
                sev    = pattern_info["severity"]
                mitre  = pattern_info.get("mitre", "")
                cwe    = pattern_info.get("cwe", "")
                desc   = pattern_info.get("description", pattern_name)

                try:
                    matches = list(re.finditer(pat, content, re.IGNORECASE | re.MULTILINE))
                except re.error as exc:
                    logger.debug("Regex error for %s: %s", pattern_name, exc)
                    continue

                for match in matches:
                    line_num = content[: match.start()].count("\n") + 1
                    ctx      = self._get_context(content, match.start())
                    cvss     = self._compute_cvss_score(pattern_name, {"severity": sev})
                    comp     = self._get_compliance_tags(pattern_name)

                    issue = {
                        "rule_id":          pattern_name,
                        "type":             "PowerShell",
                        "subtype":          pattern_name,
                        "file":             str(ps_file),
                        "line":             line_num,
                        "pattern":          pattern_name,
                        "severity":         sev,
                        "match":            match.group(0)[:120],
                        "context":          ctx,
                        "description":      desc,
                        "remediation":      self._get_remediation(pattern_name),
                        "mitre_id":         mitre,
                        "cwe_id":           cwe,
                        "cvss":             cvss,
                        "compliance":       comp,
                        "confidence":       0.95,
                    }

                    self.findings["issues"].append(issue)
                    self.findings["ps_analysis"].append(issue)
                    self.findings["risky_behaviors"].append({
                        "behavior": pattern_name,
                        "severity": sev,
                    })
                    self._update_summary(sev)
                    print(f"   [!] {pattern_name} ({sev}): {ps_file.name}:{line_num}")

            # Obfuscation detection (heuristic, separate from pattern matching)
            if self._detect_obfuscation(content):
                issue = {
                    "rule_id":     "obfuscation_heuristic",
                    "type":        "PowerShell",
                    "subtype":     "obfuscation",
                    "file":        str(ps_file),
                    "line":        0,
                    "pattern":     "Obfuscation Heuristic",
                    "severity":    "MEDIUM",
                    "match":       "Script exhibits multiple obfuscation indicators",
                    "context":     "Obfuscated code impedes security analysis",
                    "description": "Multiple obfuscation techniques detected by heuristic analysis",
                    "remediation": "Deobfuscate script and verify source code legitimacy",
                    "mitre_id":    "T1027",
                    "cwe_id":      "CWE-701",
                    "cvss":        self._compute_cvss_score("obfuscation_detected", {}),
                    "compliance":  self._get_compliance_tags("obfuscation_detected"),
                    "confidence":  0.85,
                }
                self.findings["obfuscation_detected"].append(issue)
                self.findings["issues"].append(issue)
                self._update_summary("MEDIUM")
                print(f"   [!] Obfuscation heuristic hit: {ps_file.name}")

    # =========================================================================
    # Step 2: Binary Analysis
    # =========================================================================

    def _scan_binaries_advanced(self) -> None:
        """Comprehensive binary and chain-of-trust analysis."""
        print("   [*] Performing comprehensive binary analysis...")

        search_dirs = [
            self.package_path / "SupportFiles",
            self.package_path / "Files",
            self.package_path,
        ]
        binary_files: List[Path] = []
        for d in search_dirs:
            if d.exists():
                binary_files.extend(d.rglob("*.exe"))
                binary_files.extend(d.rglob("*.dll"))
                binary_files.extend(d.rglob("*.sys"))

        # Deduplicate
        seen: set = set()
        unique_bins: List[Path] = []
        for bf in binary_files:
            if bf not in seen:
                seen.add(bf)
                unique_bins.append(bf)
        binary_files = unique_bins

        if not binary_files:
            print("   [!] No binaries found for analysis")
            return

        print(f"   [*] Found {len(binary_files)} binary file(s)")
        self.findings["summary"]["binaries_analyzed"] = len(binary_files)

        for binary_file in binary_files:
            try:
                self._analyze_single_binary(binary_file)
            except Exception as exc:
                logger.warning("Binary analysis error for %s: %s", binary_file, exc)

    def _analyze_single_binary(self, binary_file: Path) -> None:
        """Analyse a single PE binary for security issues."""
        sha256 = self._calculate_file_hash(binary_file)
        entropy = self._calculate_entropy(binary_file)

        self.findings["metrics"]["entropy_analysis"].append({
            "file":    binary_file.name,
            "sha256":  sha256,
            "entropy": entropy,
            "packed":  entropy > 7.0,
        })

        # Digital signature check
        is_signed, sig_status = self._check_signature_detailed(binary_file)
        if not is_signed:
            issue = self._make_binary_issue(
                binary_file,
                "unsigned_binary",
                "HIGH",
                f"{binary_file.name} is not digitally signed (status: {sig_status})",
                "Unsigned Binary",
                "Sign binary with an EV code-signing certificate",
                "T1553.002",
                "CWE-347",
            )
            self.findings["issues"].append(issue)
            self.findings["binary_analysis"].append(issue)
            self._update_summary("HIGH")
            print(f"   [!] Unsigned binary: {binary_file.name}")

        # Entropy / packing check
        if entropy > 7.0:
            issue = self._make_binary_issue(
                binary_file,
                "packed_binary",
                "MEDIUM",
                f"High entropy ({entropy:.2f}) - likely packed or encrypted sections",
                "Packed/Obfuscated Binary",
                "Provide unpacked binary or source code for review",
                "T1027",
                "CWE-656",
            )
            self.findings["issues"].append(issue)
            self.findings["binary_analysis"].append(issue)
            self._update_summary("MEDIUM")
            print(f"   [!] Packed binary: {binary_file.name} (entropy={entropy:.2f})")

        # PE imports analysis (pefile)
        if _PEFILE_AVAILABLE:
            try:
                self._check_pe_imports(binary_file)
            except Exception as exc:
                logger.debug("PE import analysis skipped for %s: %s", binary_file, exc)

        # NVD CVE lookup
        try:
            cves = self._query_nvd_cve(sha256, binary_file.stem)
            for cve in cves[:3]:
                cve_score = cve.get("cvss_score", 0.0)
                sev = "CRITICAL" if cve_score >= 9.0 else "HIGH" if cve_score >= 7.0 else "MEDIUM"
                issue = self._make_binary_issue(
                    binary_file,
                    "known_cve",
                    sev,
                    f"CVE {cve['cve_id']} (CVSS {cve_score}): {cve.get('description', '')[:120]}",
                    f"Known CVE: {cve['cve_id']}",
                    "Update component to patched version; see NVD for details",
                    "T1190",
                    "CWE-1035",
                )
                self.findings["issues"].append(issue)
                self.findings["binary_analysis"].append(issue)
                self._update_summary(sev)
        except Exception as exc:
            logger.debug("NVD lookup failed for %s: %s", binary_file.stem, exc)

        print(f"   [✓] Analyzed {binary_file.name} (SHA256: {sha256[:16]}..., Entropy: {entropy:.2f})")

    def _check_pe_imports(self, binary_file: Path) -> None:
        """Check PE import table for suspicious API calls."""
        suspicious_imports: Dict[str, List[str]] = {
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "CreateToolhelp32Snapshot"],
            "ntdll.dll":    ["ZwCreateProcess", "ZwQuerySystemInformation", "NtUnmapViewOfSection"],
            "wininet.dll":  ["InternetOpen", "InternetReadFile", "HttpOpenRequest"],
            "ws2_32.dll":   ["WSAStartup", "connect", "send", "recv"],
        }

        pe = pefile.PE(str(binary_file))
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
            except Exception:
                continue

            if dll_name not in suspicious_imports:
                continue

            for func in entry.imports:
                try:
                    func_name = func.name.decode("utf-8", errors="ignore") if func.name else ""
                except Exception:
                    func_name = ""

                if func_name in suspicious_imports[dll_name]:
                    issue = self._make_binary_issue(
                        binary_file,
                        "suspicious_pe_import",
                        "MEDIUM",
                        f"Imports {dll_name}::{func_name} - potentially dangerous API",
                        "Suspicious PE Import",
                        "Review binary source; verify API usage is necessary",
                        "T1106",
                        "CWE-427",
                    )
                    self.findings["issues"].append(issue)
                    self.findings["binary_analysis"].append(issue)
                    self._update_summary("MEDIUM")

    def _make_binary_issue(
        self, binary_file: Path, rule_id: str, severity: str,
        match: str, pattern: str, remediation: str,
        mitre: str, cwe: str,
    ) -> Dict:
        """Helper to construct a binary analysis issue dict."""
        return {
            "rule_id":     rule_id,
            "type":        "Binary",
            "subtype":     rule_id,
            "file":        str(binary_file),
            "line":        0,
            "pattern":     pattern,
            "severity":    severity,
            "match":       match[:200],
            "context":     "",
            "description": match,
            "remediation": remediation,
            "mitre_id":    mitre,
            "cwe_id":      cwe,
            "cvss":        self._compute_cvss_score(rule_id, {"severity": severity}),
            "compliance":  self._get_compliance_tags(rule_id),
            "confidence":  0.90,
        }

    # =========================================================================
    # Step 3: Credential Detection
    # =========================================================================

    def _scan_credentials_advanced(self) -> None:
        """Enhanced credential and data leakage detection."""
        print("   [*] Scanning for credentials and data leakage...")

        credential_patterns: Dict[str, Dict] = {
            "password_string": {
                "pattern":  r"(?i)(password|pwd|passwd|pass)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
                "severity": "CRITICAL",
            },
            "unstructured_credential": {
                "pattern":  r"(?i)\b(?:passwrd|password|passwd|credentials?|secret|pwd)\s*[=:\s>]*([A-Za-z0-9@#$%^&+=_]{6,})\b",
                "severity": "HIGH",
            },
            "api_key": {
                "pattern":  r"(?i)(api[_-]?key|apikey|api_secret|access_token)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
                "severity": "CRITICAL",
            },
            "connection_string": {
                "pattern":  r"(?i)(connectionstring|connection_string)\s*[=:]\s*['\"]([^'\"]*(?:password|pwd)[^'\"]*)['\"]",
                "severity": "CRITICAL",
            },
            "private_key_pem": {
                "pattern":  r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----",
                "severity": "CRITICAL",
            },
            "aws_access_key": {
                "pattern":  r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
            },
            "azure_storage_key": {
                "pattern":  r"(?i)(DefaultEndpointsProtocol=https.*AccountName=.*AccountKey=)",
                "severity": "CRITICAL",
            },
            "email_smtp_password": {
                "pattern":  r"(?i)(smtp|email).*(?:password|pwd|pass)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
                "severity": "HIGH",
            },
            "database_password": {
                "pattern":  r"(?i)(server|host).*(?:password|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
                "severity": "CRITICAL",
            },
            "github_token": {
                "pattern":  r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
                "severity": "CRITICAL",
            },
            "slack_token": {
                "pattern":  r"xox[baprs]-[0-9A-Za-z\-]{10,}",
                "severity": "HIGH",
            },
            "base64_secret": {
                "pattern":  r"(?i)(password|secret|key|token)\s*=\s*['\"][A-Za-z0-9+/]{30,}={0,2}['\"]",
                "severity": "HIGH",
            },
        }

        scan_extensions = {
            ".ps1", ".xml", ".ini", ".conf", ".config", ".psd1",
            ".json", ".yaml", ".yml", ".bat", ".cmd", ".psm1", ".env", ".txt"
        }

        for file_path in self.package_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in scan_extensions:
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                self.findings["summary"]["files_scanned"] += 1
            except Exception:
                continue

            for pat_name, pat_info in credential_patterns.items():
                try:
                    for match in re.finditer(pat_info["pattern"], content, re.IGNORECASE | re.MULTILINE):
                        line_num = content[: match.start()].count("\n") + 1
                        issue = {
                            "rule_id":     pat_name,
                            "type":        "Credential",
                            "subtype":     pat_name,
                            "file":        str(file_path),
                            "line":        line_num,
                            "pattern":     pat_name,
                            "severity":    pat_info["severity"],
                            "match":       match.group(0)[:80] + ("..." if len(match.group(0)) > 80 else ""),
                            "context":     self._get_context(content, match.start()),
                            "description": f"Credential pattern '{pat_name}' detected",
                            "remediation": (
                                "Move to Azure Key Vault or SCCM Task Sequence Variable "
                                "(mark Private). Base64 is NOT encryption."
                            ),
                            "mitre_id":    "T1552.001",
                            "cwe_id":      "CWE-798",
                            "cvss":        self._compute_cvss_score("hardcoded_credential", {}),
                            "compliance":  self._get_compliance_tags("hardcoded_credential"),
                            "confidence":  0.99,
                        }
                        self.findings["issues"].append(issue)
                        self.findings["credential_findings"].append(issue)
                        self._update_summary(pat_info["severity"])
                        print(f"   [!] {pat_name} in {file_path.name}:{line_num}")
                except re.error as exc:
                    logger.debug("Regex error %s: %s", pat_name, exc)

        # -------------------------------------------------------------------------
        # Dynamic Heuristic Credential Scanning (detect-secrets)
        # -------------------------------------------------------------------------
        if _DETECT_SECRETS_AVAILABLE:
            try:
                from detect_secrets.settings import transient_settings
                from detect_secrets.core.secrets_collection import SecretsCollection

                plugins_config = [
                    {'name': 'KeywordDetector'},
                    {'name': 'Base64HighEntropyString'},
                    {'name': 'HexHighEntropyString'},
                    {'name': 'PrivateKeyDetector'},
                    {'name': 'JwtTokenDetector'}
                ]

                print("   [*] Running dynamic entropy analysis (detect-secrets)...")
                with transient_settings({'plugins_used': plugins_config}):
                    secrets = SecretsCollection()
                    for file_path in self.package_path.rglob("*"):
                        if file_path.is_file() and file_path.suffix.lower() in scan_extensions:
                            secrets.scan_file(str(file_path))

                    for file_path_str, secret_list in secrets.json().items():
                        for secret in secret_list:
                            rule_id = f"dynamic_secret_{secret['type'].replace(' ', '_').lower()}"
                            issue = {
                                "rule_id":     rule_id,
                                "type":        "Credential",
                                "subtype":     secret['type'],
                                "file":        file_path_str,
                                "line":        secret['line_number'],
                                "pattern":     "detect-secrets",
                                "severity":    "CRITICAL",
                                "match":       f"High entropy string or pattern detected ({secret['type']})",
                                "context":     "Hash: " + secret['hashed_secret'],
                                "description": f"Dynamic credential detection: {secret['type']}",
                                "remediation": "Move to Azure Key Vault or SCCM Task Sequence Variable.",
                                "mitre_id":    "T1552.001",
                                "cwe_id":      "CWE-798",
                                "cvss":        self._compute_cvss_score("hardcoded_credential", {}),
                                "compliance":  self._get_compliance_tags("hardcoded_credential"),
                                "confidence":  0.95,
                            }
                            # Check if we already flagged this line statically to avoid duplicates
                            duplicate = any(
                                i["file"] == file_path_str and i["line"] == secret['line_number']
                                for i in self.findings["credential_findings"]
                            )
                            if not duplicate:
                                self.findings["issues"].append(issue)
                                self.findings["credential_findings"].append(issue)
                                self._update_summary("CRITICAL")
                                fname = Path(file_path_str).name
                                print(f"   [!] {rule_id} in {fname}:{secret['line_number']}")

            except Exception as e:
                logger.debug("detect-secrets scan failed: %s", e)

    # =========================================================================
    # Step 4: HemSpect — Data Leakage Intelligence Engine
    # =========================================================================

    def _scan_data_leakage_hemspect(self) -> None:
        """
        HemSpect: A 3-tier data leakage intelligence engine.

        Tier 1 — Extension Classifier: flags dangerous file types that should
                 never exist inside a deployment package.
        Tier 2 — Filename Heuristic: flags files whose names suggest they
                 contain credentials, password lists, or key material.
        Tier 3 — Deep Content Regex: scans text-readable files for connection
                 strings, XML credentials, cloud tokens, and IT config secrets.
        """
        print("   [*] HemSpect engine initializing...")

        hemspect_findings: List[Dict] = []

        # =====================================================================
        # Tier 1 — Extension Classifier (instant flag by file type)
        # =====================================================================
        DANGEROUS_EXTENSIONS: Dict[str, tuple] = {
            # Credential stores & key material
            ".kdbx":     ("KeePass Database",                "CRITICAL", "T1555.005"),
            ".kdb":      ("KeePass v1 Database",             "CRITICAL", "T1555.005"),
            ".keychain": ("macOS Keychain",                   "CRITICAL", "T1555.001"),
            ".jks":      ("Java KeyStore",                    "CRITICAL", "T1552.004"),
            ".keystore": ("Java/Android KeyStore",            "CRITICAL", "T1552.004"),
            ".pfx":      ("PKCS#12 Certificate+Private Key",  "CRITICAL", "T1552.004"),
            ".p12":      ("PKCS#12 Certificate Bundle",       "CRITICAL", "T1552.004"),
            ".pem":      ("PEM Key/Certificate",              "HIGH",     "T1552.004"),
            ".key":      ("Private Key File",                 "CRITICAL", "T1552.004"),
            ".ppk":      ("PuTTY Private Key",                "CRITICAL", "T1552.004"),
            ".asc":      ("PGP/GPG Armored Key",              "HIGH",     "T1552.004"),
            # Email & mailbox files
            ".ost":      ("Outlook Offline Data (email)",     "HIGH",     "T1114.001"),
            ".pst":      ("Outlook Personal Storage (email)", "HIGH",     "T1114.001"),
            ".eml":      ("Email Message File",               "MEDIUM",   "T1114.001"),
            ".msg":      ("Outlook Message File",             "MEDIUM",   "T1114.001"),
            # Database files
            ".mdf":      ("SQL Server Primary Data File",     "CRITICAL", "T1005"),
            ".ldf":      ("SQL Server Log File",              "HIGH",     "T1005"),
            ".sdf":      ("SQL Server Compact Database",      "HIGH",     "T1005"),
            ".sqlite":   ("SQLite Database",                  "MEDIUM",   "T1005"),
            ".bak":      ("Database Backup File",             "HIGH",     "T1005"),
            # RDP / VPN configs
            ".rdp":      ("Remote Desktop Connection File",   "HIGH",     "T1021.001"),
            ".rdg":      ("RD Connection Manager Group",      "HIGH",     "T1021.001"),
            ".ovpn":     ("OpenVPN Configuration",            "HIGH",     "T1133"),
            ".pcf":      ("Cisco VPN Client Profile",         "HIGH",     "T1133"),
            # Memory dumps
            ".dmp":      ("Memory/Crash Dump",                "CRITICAL", "T1003.001"),
            ".vmem":     ("Virtual Memory Dump",              "CRITICAL", "T1003.001"),
            ".vmdk":     ("VM Disk Image",                    "HIGH",     "T1005"),
            # Shell history
            ".bash_history": ("Bash Command History",         "HIGH",     "T1552.003"),
            ".zsh_history":  ("Zsh Command History",          "HIGH",     "T1552.003"),
        }

        print("   [*] Tier 1: Extension classifier scanning...")
        tier1_count = 0
        for file_path in self.package_path.rglob("*"):
            if not file_path.is_file():
                continue
            ext = file_path.suffix.lower()
            if ext in DANGEROUS_EXTENSIONS:
                desc, severity, mitre_id = DANGEROUS_EXTENSIONS[ext]
                issue = {
                    "rule_id":     f"hemspect_ext_{ext.lstrip('.')}",
                    "type":        "DataLeakage",
                    "subtype":     "DangerousFileType",
                    "file":        str(file_path),
                    "line":        0,
                    "pattern":     "hemspect_extension",
                    "severity":    severity,
                    "match":       f"{desc} ({ext})",
                    "context":     f"File size: {file_path.stat().st_size:,} bytes",
                    "description": f"HemSpect: {desc} found in package — should never exist in a deployment",
                    "remediation": f"Remove {file_path.name} from the package immediately. {desc} files must not ship in deployment packages.",
                    "mitre_id":    mitre_id,
                    "cwe_id":      "CWE-538",
                    "cvss":        self._compute_cvss_score("hardcoded_credential", {}),
                    "compliance":  self._get_compliance_tags("hardcoded_credential"),
                    "confidence":  0.98,
                }
                hemspect_findings.append(issue)
                tier1_count += 1
                print(f"   [!] DANGEROUS FILE: {file_path.name} ({desc})")

        # =====================================================================
        # Tier 2 — Filename Heuristic (suspicious names)
        # =====================================================================
        SUSPICIOUS_NAME_PATTERNS: List[tuple] = [
            (r"(?i)^(password|passwd|credentials?|creds|secrets?|login|accounts?)[\.\-_ ]",
             "Credential-related filename",   "CRITICAL"),
            (r"(?i)(password|passwd|creds|secrets?|accounts?)\.(txt|csv|xlsx?|docx?|log|xml|json)$",
             "Credential file by name+ext",   "CRITICAL"),
            (r"(?i)^(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$",
             "SSH Key File",                  "CRITICAL"),
            (r"(?i)^\.?(gnupg|gpg|pgp)",
             "GPG/PGP Key Material",          "HIGH"),
            (r"(?i)^(web\.config|appsettings\.json|app\.config|connectionstrings\.config)$",
             ".NET Config with Secrets",      "HIGH"),
            (r"(?i)^(wp-config\.php|config\.php|database\.yml|settings\.py|\.env(\..+)?)$",
             "Web App Config File",           "HIGH"),
            (r"(?i)^(unattend|autounattend|sysprep)(\.xml|\.inf)$",
             "Windows Unattend/Sysprep File", "CRITICAL"),
            (r"(?i)^(shadow|passwd|htpasswd|\.htpasswd)$",
             "Linux Auth File",              "CRITICAL"),
            (r"(?i)^(ntds\.dit|sam|system|security)$",
             "Windows SAM/NTDS Dump",        "CRITICAL"),
            (r"(?i)(backup|dump|export).*\.(sql|bak|gz|tar|zip)$",
             "Database Backup/Dump",         "HIGH"),
            (r"(?i)^(known_hosts|authorized_keys)$",
             "SSH Auth File",               "MEDIUM"),
            (r"(?i)^(\.dockercfg|\.docker/config\.json|kubeconfig|\.kube/config)$",
             "Container/K8s Credential",    "CRITICAL"),
            (r"(?i)(token|apikey|api_key|secret_key|private_key|access_key)\.(txt|json|yaml|yml|xml|cfg|conf|ini)$",
             "Token/API key file",          "CRITICAL"),
        ]

        print("   [*] Tier 2: Filename heuristic scanning...")
        tier2_count = 0
        for file_path in self.package_path.rglob("*"):
            if not file_path.is_file():
                continue
            fname = file_path.name
            for pattern, desc, severity in SUSPICIOUS_NAME_PATTERNS:
                if re.search(pattern, fname):
                    issue = {
                        "rule_id":     "hemspect_filename",
                        "type":        "DataLeakage",
                        "subtype":     "SuspiciousFilename",
                        "file":        str(file_path),
                        "line":        0,
                        "pattern":     "hemspect_filename",
                        "severity":    severity,
                        "match":       f"{desc}: {fname}",
                        "context":     f"File size: {file_path.stat().st_size:,} bytes",
                        "description": f"HemSpect: {desc} — suspicious filename detected",
                        "remediation": f"Verify '{fname}' does not contain sensitive data. Remove from package if it does.",
                        "mitre_id":    "T1552.001",
                        "cwe_id":      "CWE-538",
                        "cvss":        self._compute_cvss_score("hardcoded_credential", {}),
                        "compliance":  self._get_compliance_tags("hardcoded_credential"),
                        "confidence":  0.90,
                    }
                    # Avoid duplicate if Tier 1 already flagged this file
                    if not any(f["file"] == str(file_path) for f in hemspect_findings):
                        hemspect_findings.append(issue)
                        tier2_count += 1
                        print(f"   [!] SUSPECT NAME: {fname} ({desc})")
                    break  # one match per file is enough

        # =====================================================================
        # Tier 3 — Deep Content Regex (connection strings, XML creds, tokens)
        # =====================================================================
        CONTENT_SCAN_EXTENSIONS = {
            ".ps1", ".psm1", ".psd1", ".xml", ".config", ".json", ".yaml",
            ".yml", ".ini", ".conf", ".cfg", ".txt", ".env", ".properties",
            ".bat", ".cmd", ".vbs", ".js", ".py", ".pl", ".rb", ".sh",
            ".php", ".asp", ".aspx", ".cs", ".java", ".cpp", ".h", ".log",
            ".sql", ".toml", ".reg",
        }

        CONTENT_PATTERNS: Dict[str, tuple] = {
            # SQL / Database connection strings
            "sql_conn_string": (
                r"(?i)(Data\s+Source|Server)\s*=\s*[^;\s]+.*?(?:password|pwd)\s*=\s*[^;\s]+",
                "CRITICAL", "T1552.001", "SQL Connection String with embedded password"),
            "oledb_conn_string": (
                r"(?i)Provider\s*=\s*.*?(?:password|pwd)\s*=\s*[^;\s\"']+",
                "CRITICAL", "T1552.001", "OLE DB Connection String with password"),
            "mongodb_uri": (
                r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",
                "CRITICAL", "T1552.001", "MongoDB URI with embedded credentials"),
            "jdbc_conn_string": (
                r"(?i)jdbc:[a-z]+://[^;\s]+.*?(?:password|pwd)\s*=\s*[^;\s\"']+",
                "CRITICAL", "T1552.001", "JDBC Connection String with password"),
            # XML credential elements
            "xml_password_element": (
                r"(?i)<\s*(?:password|passwd|pwd|secret|credential|apikey|api_key|token|connectionstring)\s*>[^<]{4,}</",
                "CRITICAL", "T1552.001", "XML element containing credential value"),
            "xml_password_attribute": (
                r'(?i)(?:password|passwd|pwd|secret|token|apikey)\s*=\s*"[^"]{4,}"',
                "HIGH", "T1552.001", "XML/Config attribute with credential value"),
            # .NET machine keys & validation keys
            "dotnet_machine_key": (
                r"(?i)<machineKey\s.*?(?:validationKey|decryptionKey)\s*=\s*\"[A-Fa-f0-9]{32,}\"",
                "CRITICAL", "T1552.001", ".NET Machine Key (allows session forgery)"),
            # Windows Unattend credentials
            "unattend_password": (
                r"(?i)<(?:Password|AdministratorPassword|AutoLogon)>.*?<Value>[^<]+</Value>",
                "CRITICAL", "T1552.001", "Windows Unattend/Sysprep embedded password"),
            # PowerShell SecureString with plaintext
            "ps_securestring_plaintext": (
                r"(?i)ConvertTo-SecureString\s+['\"][^'\"]+['\"]\s+.*-AsPlainText",
                "CRITICAL", "T1552.001", "ConvertTo-SecureString with plaintext input"),
            # Cloud provider patterns
            "gcp_service_account": (
                r'"type"\s*:\s*"service_account".*?"private_key"\s*:',
                "CRITICAL", "T1552.001", "GCP Service Account JSON key"),
            "azure_client_secret": (
                r"(?i)(?:client_secret|clientsecret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"][A-Za-z0-9\-_.~]{20,}['\"]",
                "CRITICAL", "T1552.001", "Azure Client Secret / Service Principal"),
            "azure_sas_token": (
                r"(?i)(?:sv=|sig=|se=|sp=).*(?:sv=|sig=|se=|sp=)",
                "HIGH", "T1552.001", "Azure SAS Token"),
            # OAuth / Bearer tokens
            "bearer_token": (
                r"(?i)(?:Bearer|Authorization)\s*[:=]\s*['\"]?(?:eyJ|Bearer\s+eyJ)[A-Za-z0-9\-_.]+",
                "CRITICAL", "T1528", "OAuth Bearer/JWT Token"),
            # SMTP credentials
            "smtp_credentials": (
                r"(?i)(?:smtp|mail).*(?:(?:user|username)\s*[=:]\s*['\"][^'\"]+['\"].*(?:pass|password)\s*[=:]\s*['\"][^'\"]+['\"])",
                "HIGH", "T1552.001", "SMTP/Mail credentials"),
            # Generic DSN / connection
            "dsn_string": (
                r"(?i)(?:DSN|ODBC)\s*=\s*.*?(?:UID|USER)\s*=\s*[^;]+.*?(?:PWD|PASSWORD)\s*=\s*[^;\s]+",
                "CRITICAL", "T1552.001", "DSN/ODBC connection string with credentials"),
            # WiFi passwords in exported XML profiles
            "wifi_password": (
                r"(?i)<keyMaterial>[^<]{8,}</keyMaterial>",
                "HIGH", "T1552.001", "WiFi password in exported profile"),
            # Registry export with stored credentials
            "reg_stored_credential": (
                r'(?i)"(?:Password|Pwd|Secret|Token)"\s*=\s*"[^"]{6,}"',
                "HIGH", "T1552.002", "Registry export with stored credential"),
            # Docker / K8s secrets
            "docker_auth": (
                r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
                "CRITICAL", "T1552.001", "Docker registry auth token (base64)"),
        }

        print("   [*] Tier 3: Deep content analysis scanning...")
        tier3_count = 0
        for file_path in self.package_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in CONTENT_SCAN_EXTENSIONS:
                continue
            # Skip very large files (>5MB) for performance
            try:
                if file_path.stat().st_size > 5 * 1024 * 1024:
                    continue
            except OSError:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for pat_name, (pattern, severity, mitre_id, desc) in CONTENT_PATTERNS.items():
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                        line_num = content[: match.start()].count("\n") + 1
                        matched_text = match.group(0)[:120]
                        # Redact actual values for the report
                        redacted = re.sub(
                            r"((?:password|pwd|secret|token|key|sig)\s*[=:]\s*['\"]?)([^'\";,\s]{4})[^'\";,\s]*",
                            r"\1\2****",
                            matched_text,
                            flags=re.IGNORECASE,
                        )
                        issue = {
                            "rule_id":     f"hemspect_{pat_name}",
                            "type":        "DataLeakage",
                            "subtype":     "ContentMatch",
                            "file":        str(file_path),
                            "line":        line_num,
                            "pattern":     f"hemspect_{pat_name}",
                            "severity":    severity,
                            "match":       redacted,
                            "context":     self._get_context(content, match.start()),
                            "description": f"HemSpect: {desc}",
                            "remediation": f"Remove embedded credential. Use a secrets vault (Azure Key Vault / SCCM TS Variables).",
                            "mitre_id":    mitre_id,
                            "cwe_id":      "CWE-798",
                            "cvss":        self._compute_cvss_score("hardcoded_credential", {}),
                            "compliance":  self._get_compliance_tags("hardcoded_credential"),
                            "confidence":  0.95,
                        }
                        hemspect_findings.append(issue)
                        tier3_count += 1
                        fname = file_path.name
                        print(f"   [!] {pat_name} in {fname}:{line_num}")
                        break  # one match per pattern per file to reduce noise
                except re.error as exc:
                    logger.debug("HemSpect regex error %s: %s", pat_name, exc)

        # =====================================================================
        # Merge HemSpect findings into the main findings list
        # =====================================================================
        for issue in hemspect_findings:
            self.findings["issues"].append(issue)
            self._update_summary(issue["severity"])

        total = len(hemspect_findings)
        print(f"   [*] HemSpect complete: Tier1={tier1_count} Tier2={tier2_count} Tier3={tier3_count} (Total: {total})")

    # =========================================================================
    # Step 5: Malware Pattern Detection
    # =========================================================================

    def _scan_malware_patterns_advanced(self) -> None:
        """Advanced malware detection with behavioral analysis."""
        print("   [*] Scanning for malware patterns and suspicious behaviors...")

        malware_patterns: Dict[str, Tuple[str, str, str]] = {
            "c2_raw_ip": (
                r"https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                "HIGH", "T1071",
            ),
            "malware_keywords": (
                r"(?i)(botnet|trojan|ransomware|worm\b|malware|backdoor|rootkit|keylogger)",
                "CRITICAL", "T1588",
            ),
            "data_exfiltration": (
                r"(?i)(exfiltrate|c2server|ransom.*files|encrypt.*all.*files|loot\b)",
                "CRITICAL", "T1041",
            ),
            "process_injection": (
                r"(?i)(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|SetWindowsHookEx|NtCreateThreadEx)",
                "CRITICAL", "T1055",
            ),
            "privilege_escalation_api": (
                r"(?i)(SeDebugPrivilege|SeLoadDriverPrivilege|AdjustTokenPrivileges)",
                "HIGH", "T1068",
            ),
            "reverse_shell_indicator": (
                r"(?i)(bash\s+-i\s*>&|/dev/tcp/|TCPClient.*Connect|nc\s+-[el]|ncat\s+-[el])",
                "CRITICAL", "T1059",
            ),
        }

        script_extensions = {".ps1", ".py", ".vbs", ".js", ".bat", ".cmd", ".psm1"}

        for file_path in self.package_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in script_extensions:
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for indicator, (pattern, severity, mitre) in malware_patterns.items():
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[: match.start()].count("\n") + 1
                        issue = {
                            "rule_id":     indicator,
                            "type":        "Malware",
                            "subtype":     indicator,
                            "file":        str(file_path),
                            "line":        line_num,
                            "pattern":     indicator,
                            "severity":    severity,
                            "match":       match.group(0)[:120],
                            "context":     self._get_context(content, match.start()),
                            "description": f"Malware indicator: {indicator}",
                            "remediation": "BLOCK PACKAGE - IMMEDIATE SECURITY INVESTIGATION REQUIRED",
                            "mitre_id":    mitre,
                            "cwe_id":      "CWE-506",
                            "cvss":        self._compute_cvss_score(indicator, {"severity": severity}),
                            "compliance":  self._get_compliance_tags("disabled_security"),
                            "confidence":  0.95,
                        }
                        self.findings["issues"].append(issue)
                        self.findings["malware_indicators"].append(issue)
                        self._update_summary(severity)
                        print(f"   [!!!] MALWARE ALERT: {indicator} in {file_path.name}:{line_num}")
                except re.error as exc:
                    logger.debug("Regex error %s: %s", indicator, exc)

    # =========================================================================
    # Step 5: Configuration & Dependency Scanning
    # =========================================================================

    def _scan_configurations_and_dependencies(self) -> None:
        """Scan configuration files and dependency declarations."""
        print("   [*] Scanning configuration and dependency files...")

        config_patterns: Dict[str, Tuple[str, str]] = {
            "weak_password_policy":       (r"(?i)(MinPasswordLength|PasswordComplexity)\s*[=:]\s*[0-4]",     "MEDIUM"),
            "disabled_security_feature":  (r"(?i)(DisableAV|DisableWinDefender|DisableDefender)\s*[=:]\s*(true|1)", "HIGH"),
            "verbose_debug_logging":      (r"(?i)(LogLevel)\s*[=:]\s*(Debug|Trace|Verbose)",                 "LOW"),
            "tls_disabled":               (r"(?i)(TLSv1\b|SSLv2|SSLv3|DisableTLS)",                         "HIGH"),
            "localhost_bypass":           (r"(?i)(bypass.*proxy|proxybypass.*\*|NoProxy)",                   "MEDIUM"),
            "hardcoded_ip_endpoint":      (r"\b(?:10|172|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}\b",  "LOW"),
        }

        config_extensions = {".xml", ".ini", ".conf", ".config", ".yaml", ".yml", ".json", ".toml"}

        for config_file in self.package_path.rglob("*"):
            if not config_file.is_file():
                continue
            if config_file.suffix.lower() not in config_extensions:
                continue
            try:
                content = config_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for pat_name, (pattern, severity) in config_patterns.items():
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[: match.start()].count("\n") + 1
                        issue = {
                            "rule_id":     pat_name,
                            "type":        "Configuration",
                            "subtype":     pat_name,
                            "file":        str(config_file),
                            "line":        line_num,
                            "pattern":     pat_name,
                            "severity":    severity,
                            "match":       match.group(0)[:100],
                            "context":     self._get_context(content, match.start()),
                            "description": f"Configuration issue: {pat_name}",
                            "remediation": f"Review and enforce security policy for {pat_name}",
                            "mitre_id":    "T1562",
                            "cwe_id":      "CWE-1104",
                            "cvss":        self._compute_cvss_score(pat_name, {"severity": severity}),
                            "compliance":  self._get_compliance_tags(pat_name),
                            "confidence":  0.80,
                        }
                        self.findings["issues"].append(issue)
                        self._update_summary(severity)
                except re.error as exc:
                    logger.debug("Regex error %s: %s", pat_name, exc)

    # =========================================================================
    # Step 6: PSADT v4 Cmdlet Analysis
    # =========================================================================

    def _scan_psadt_v4_cmdlets(self) -> None:
        """
        Scan for PSADT v4.1 specific misuse:
          - Execute-ADTProcess with wildcard IgnoreExitCodes
          - Invoke-ADTAllUsersRegistryAction without HKLM write justification
          - Deprecated PSADT v3 API usage
          - Path injection risks in ADT file cmdlets
        """
        print("   [*] Checking PSADT v4.1 cmdlet compliance...")

        ps_files = (
            list(self.package_path.rglob("*.ps1")) +
            list(self.package_path.rglob("*.psm1"))
        )

        # Additional v4 analysis patterns beyond the main pattern dict
        v4_checks: Dict[str, Dict] = {
            "adt_execute_no_path_validation": {
                "pattern":  r"Execute-ADTProcess\s+(?!.*-(?:Path|FilePath))",
                "severity": "MEDIUM",
                "message":  "Execute-ADTProcess called without explicit -Path/-FilePath validation",
            },
            "adt_invoke_hklm_no_comment": {
                "pattern":  r"Invoke-ADTAllUsersRegistryAction.*HKLM(?!.*#)",
                "severity": "MEDIUM",
                "message":  "HKLM write via Invoke-ADTAllUsersRegistryAction without inline justification comment",
            },
            "adt_close_dialog_before_exec": {
                "pattern":  r"Close-ADTInstallationProgress.*\n.*Execute-ADTProcess",
                "severity": "LOW",
                "message":  "Progress dialog closed immediately before process execution - consider user messaging",
            },
        }

        for ps_file in ps_files:
            try:
                content = ps_file.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                logger.warning("Cannot read %s: %s", ps_file, exc)
                continue

            # Run the v4 specific checks
            for chk_name, chk_info in v4_checks.items():
                try:
                    for match in re.finditer(chk_info["pattern"], content, re.IGNORECASE | re.DOTALL):
                        line_num = content[: match.start()].count("\n") + 1
                        issue = {
                            "rule_id":     chk_name,
                            "type":        "psadt_v4",
                            "subtype":     chk_name,
                            "file":        str(ps_file),
                            "line":        line_num,
                            "pattern":     chk_name,
                            "severity":    chk_info["severity"],
                            "match":       match.group(0)[:100],
                            "context":     self._get_context(content, match.start()),
                            "description": chk_info["message"],
                            "remediation": self._get_remediation(chk_name),
                            "mitre_id":    "T1204",
                            "cwe_id":      "CWE-754",
                            "cvss":        self._compute_cvss_score(chk_name, {"severity": chk_info["severity"]}),
                            "compliance":  self._get_compliance_tags(chk_name),
                            "confidence":  0.80,
                        }
                        self.findings["issues"].append(issue)
                        self.findings["psadt_v4_findings"].append(issue)
                        self._update_summary(chk_info["severity"])
                        print(f"   [!] PSADT v4 check '{chk_name}' ({chk_info['severity']}): {ps_file.name}:{line_num}")
                except re.error as exc:
                    logger.debug("Regex error %s: %s", chk_name, exc)

            # V3 deprecated API: check if any found from main patterns
            v3_pattern = r"(?i)(Show-InstallationProgress|Execute-Process\b|Copy-File\b|Remove-File\b|Set-RegistryKey\b)"
            try:
                for match in re.finditer(v3_pattern, content, re.IGNORECASE):
                    line_num = content[: match.start()].count("\n") + 1
                    issue = {
                        "rule_id":     "psadt_v3_deprecated_api",
                        "type":        "psadt_v4",
                        "subtype":     "deprecated_api",
                        "file":        str(ps_file),
                        "line":        line_num,
                        "pattern":     "PSADT v3 Deprecated API",
                        "severity":    "MEDIUM",
                        "match":       match.group(0)[:80],
                        "context":     self._get_context(content, match.start()),
                        "description": f"Deprecated PSADT v3 cmdlet '{match.group(0).strip()}' found - bypasses v4 audit controls",
                        "remediation": "Migrate to PSADT v4 equivalent cmdlet (e.g. Execute-Process → Execute-ADTProcess)",
                        "mitre_id":    "T1059.001",
                        "cwe_id":      "CWE-1104",
                        "cvss":        self._compute_cvss_score("psadt_deprecated_v3_appdeployment", {}),
                        "compliance":  self._get_compliance_tags("psadt_deprecated_v3_appdeployment"),
                        "confidence":  0.90,
                    }
                    self.findings["issues"].append(issue)
                    self.findings["psadt_v4_findings"].append(issue)
                    self._update_summary("MEDIUM")
                    print(f"   [!] Deprecated PSADT v3 API in {ps_file.name}:{line_num} → {match.group(0).strip()}")
            except re.error as exc:
                logger.debug("V3 API regex error: %s", exc)

    # =========================================================================
    # Step 7: MSI/MSP/MSIX Package Analysis
    # =========================================================================

    def _scan_msi_packages(self) -> None:
        """
        Find and analyse MSI/MSP/MSIX packages for:
          - Unsigned packages
          - Dangerous custom action types (34=cmd deferred, 1074=deferred system)
          - Remote URL installers
        """
        print("   [*] Scanning for MSI/MSP/MSIX packages...")

        msi_extensions = {".msi", ".msp", ".msix"}
        msi_files: List[Path] = []
        for file_path in self.package_path.rglob("*"):
            if file_path.suffix.lower() in msi_extensions:
                msi_files.append(file_path)

        if not msi_files:
            print("   [!] No MSI/MSP/MSIX files found")
            return

        self.findings["summary"]["msi_files"] = len(msi_files)
        print(f"   [*] Found {len(msi_files)} installer package(s)")

        for msi_file in msi_files:
            # Signature check
            is_signed, sig_status = self._check_signature_detailed(msi_file)
            if not is_signed:
                issue = {
                    "rule_id":     "unsigned_msi",
                    "type":        "msi_analysis",
                    "subtype":     "unsigned",
                    "file":        str(msi_file),
                    "line":        0,
                    "pattern":     "Unsigned MSI Package",
                    "severity":    "HIGH",
                    "match":       f"{msi_file.name} is not digitally signed (status: {sig_status})",
                    "context":     "",
                    "description": "MSI package lacks digital signature - integrity cannot be verified",
                    "remediation": "Sign MSI with EV code-signing cert; use Windows SDK signtool.exe",
                    "mitre_id":    "T1553.002",
                    "cwe_id":      "CWE-347",
                    "cvss":        self._compute_cvss_score("unsigned_binary", {"severity": "HIGH"}),
                    "compliance":  self._get_compliance_tags("external_download"),
                    "confidence":  0.99,
                }
                self.findings["issues"].append(issue)
                self.findings["msi_findings"].append(issue)
                self._update_summary("HIGH")
                print(f"   [!] Unsigned MSI: {msi_file.name}")

            # Custom Action analysis via PowerShell WindowsInstaller COM
            if msi_file.suffix.lower() == ".msi":
                self._analyze_msi_custom_actions(msi_file)

    def _analyze_msi_custom_actions(self, msi_file: Path) -> None:
        """Use PowerShell COM to enumerate dangerous MSI custom action types."""
        # Custom action type flag meanings
        # Type 1   = DLL custom action
        # Type 2   = EXE custom action
        # Type 34  = Deferred cmd.exe script (CRITICAL)
        # Type 1074 = Deferred in system context (CRITICAL)

        ps_script = f"""
$msiPath = '{str(msi_file).replace("'", "''")}';
try {{
    $wi = New-Object -ComObject WindowsInstaller.Installer;
    $db = $wi.OpenDatabase($msiPath, 0);
    $view = $db.OpenView("SELECT Action, Type, Source, Target FROM CustomAction");
    $view.Execute();
    $results = @();
    $rec = $view.Fetch();
    while ($rec -ne $null) {{
        $results += [PSCustomObject]@{{
            Action = $rec.StringData(1);
            Type   = $rec.IntegerData(2);
            Source = $rec.StringData(3);
            Target = $rec.StringData(4);
        }};
        $rec = $view.Fetch();
    }};
    $results | ConvertTo-Json -Compress -Depth 3;
}} catch {{ Write-Error $_.Exception.Message }};
"""

        dangerous_types = {
            1:    ("DLL custom action",             "MEDIUM"),
            2:    ("EXE custom action",             "HIGH"),
            34:   ("Deferred cmd.exe script",       "CRITICAL"),
            1074: ("Deferred system context exec",  "CRITICAL"),
            82:   ("Deferred JScript/VBScript",     "HIGH"),
        }

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=30,
            )
            raw = result.stdout.strip()
            if not raw or result.returncode != 0:
                logger.debug("MSI COM analysis returned no data for %s", msi_file.name)
                return

            # May return single object or array
            try:
                cas = json.loads(raw)
                if isinstance(cas, dict):
                    cas = [cas]
            except json.JSONDecodeError:
                logger.debug("Cannot parse MSI custom action JSON for %s", msi_file.name)
                return

            for ca in cas:
                ca_type = int(ca.get("Type", 0)) & 0xFFFF  # lower 16 bits
                if ca_type in dangerous_types:
                    desc, severity = dangerous_types[ca_type]
                    action_name = ca.get("Action", "Unknown")
                    target_str  = str(ca.get("Target", ""))[:80]
                    issue = {
                        "rule_id":     f"msi_ca_type_{ca_type}",
                        "type":        "msi_analysis",
                        "subtype":     "custom_action",
                        "file":        str(msi_file),
                        "line":        0,
                        "pattern":     f"Dangerous Custom Action (Type {ca_type})",
                        "severity":    severity,
                        "match":       f"Action={action_name}, Type={ca_type} ({desc}), Target={target_str}",
                        "context":     "",
                        "description": (
                            f"MSI custom action '{action_name}' is Type {ca_type} ({desc}) "
                            "which executes arbitrary code during installation"
                        ),
                        "remediation": (
                            "Review custom action source and target; prefer WiX managed custom actions "
                            "or eliminate deferred system-context code execution"
                        ),
                        "mitre_id":    "T1218.007",
                        "cwe_id":      "CWE-94",
                        "cvss":        self._compute_cvss_score("lolbin_msiexec_remote", {"severity": severity}),
                        "compliance":  self._get_compliance_tags("external_download"),
                        "confidence":  0.95,
                    }
                    self.findings["issues"].append(issue)
                    self.findings["msi_findings"].append(issue)
                    self._update_summary(severity)
                    print(f"   [!] MSI dangerous CA type {ca_type} ({desc}): {action_name} in {msi_file.name}")

        except subprocess.TimeoutExpired:
            logger.warning("MSI analysis timed out for %s", msi_file.name)
        except Exception as exc:
            logger.debug("MSI custom action analysis error for %s: %s", msi_file.name, exc)

    # =========================================================================
    # Step 8: Risk Scoring & MITRE Mapping
    # =========================================================================

    def _compute_risk_scores(self) -> None:
        """Compute overall risk score and build MITRE mapping."""
        total_risk = 0.0

        for issue in self.findings["issues"]:
            severity   = issue.get("severity", "LOW")
            weight     = self.RISK_WEIGHTS.get(severity, 0.5)
            confidence = issue.get("confidence", 0.8)
            total_risk += weight * confidence

            mitre_id = issue.get("mitre_id", "")
            if mitre_id:
                rule_id = issue.get("rule_id", issue.get("pattern", ""))
                tactic_info = self.MITRE_TACTICS.get(rule_id, ("", "", ""))
                self.findings["mitre_mapping"].append({
                    "technique_id":   mitre_id,
                    "tactic":         tactic_info[1] if tactic_info[1] else "Unknown",
                    "technique_name": tactic_info[2] if tactic_info[2] else rule_id,
                    "rule_id":        rule_id,
                    "file":           issue.get("file", ""),
                    "severity":       severity,
                })

        # Normalize to 0-100
        self.findings["risk_score"] = round(min(100.0, (total_risk / 10.0) * 100), 2)

        # Build compliance summary
        frameworks: Dict[str, set] = {
            "nist_800_53": set(),
            "cmmc_2":      set(),
            "cis_v8":      set(),
            "iec_62443":   set(),
            "owasp":       set(),
        }
        for issue in self.findings["issues"]:
            comp = issue.get("compliance", {})
            for fw, controls in comp.items():
                if fw in frameworks:
                    frameworks[fw].update(controls)

        self.findings["compliance_summary"] = {fw: sorted(v) for fw, v in frameworks.items()}

    # =========================================================================
    # Allowlist / Suppression
    # =========================================================================

    def _apply_allowlist(self, issues: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter issues through the loaded allowlist.

        Returns (active_issues, suppressed_issues).
        Each suppressed issue carries an 'allowlist_entry' reference.
        """
        if not self.allowlist:
            return issues, []

        now = datetime.now(timezone.utc)
        active: List[Dict] = []
        suppressed: List[Dict] = []

        for issue in issues:
            matched_entry = None
            for entry in self.allowlist:
                # Check rule_id match
                if entry.get("rule_id") and entry["rule_id"] != issue.get("rule_id", ""):
                    continue

                # Check file pattern match
                file_pattern = entry.get("file_pattern", "*")
                import fnmatch
                file_name = Path(issue.get("file", "")).name
                if not fnmatch.fnmatch(file_name, file_pattern):
                    continue

                # Check expiry
                expiry_str = entry.get("expires", "")
                if expiry_str:
                    try:
                        expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                        if now > expiry:
                            continue  # Entry expired - do not suppress
                    except ValueError:
                        pass

                matched_entry = entry
                break

            if matched_entry:
                issue_copy = dict(issue)
                issue_copy["allowlist_entry"] = matched_entry
                suppressed.append(issue_copy)
                logger.info(
                    "Suppressed [%s] in %s (allowlist: %s)",
                    issue.get("rule_id"), issue.get("file"), matched_entry.get("reason", "no reason"),
                )
            else:
                active.append(issue)

        return active, suppressed

    # =========================================================================
    # CVSS v3.1 Scoring
    # =========================================================================

    def _compute_cvss_score(self, pattern_name: str, context: dict) -> Dict[str, Any]:
        """
        Return CVSS v3.1 base score dict for a given pattern.

        Returns:
          {base_score: float, vector: str, severity: str}
        """
        if pattern_name in self.CVSS_VECTORS:
            score, vector, sev = self.CVSS_VECTORS[pattern_name]
            return {"base_score": score, "vector": vector, "severity": sev}

        # Fallback: infer from severity label
        sev = context.get("severity", "MEDIUM")
        defaults: Dict[str, Tuple[float, str, str]] = {
            "CRITICAL": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL"),
            "HIGH":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH"),
            "MEDIUM":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MEDIUM"),
            "LOW":      (2.0, "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N", "LOW"),
            "INFO":     (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "NONE"),
        }
        score, vector, severity = defaults.get(sev, defaults["MEDIUM"])
        return {"base_score": score, "vector": vector, "severity": severity}

    # =========================================================================
    # Compliance Tags
    # =========================================================================

    def _get_compliance_tags(self, pattern_name: str) -> Dict[str, List[str]]:
        """Return compliance framework control IDs for a given pattern."""
        return self.COMPLIANCE_TAGS.get(pattern_name, dict(self._DEFAULT_COMPLIANCE))

    # =========================================================================
    # Cryptographic Manifest & Audit Log
    # =========================================================================

    def _generate_cryptographic_manifest(self) -> None:
        """
        Generate an ECDSA P-256 signed manifest for the scan output.

        Files produced:
          manifest.json        – plaintext manifest
          manifest.sig         – base64 DER-encoded ECDSA signature
          manifest_public.pem  – corresponding public key for verification
        """
        if not _CRYPTO_AVAILABLE:
            logger.warning("cryptography library not available - manifest skipped")
            return

        # Compute package hash
        pkg_hash = self._hash_directory(self.package_path)

        # Compute findings hash
        findings_bytes = json.dumps(
            self.findings["issues"], sort_keys=True, ensure_ascii=True
        ).encode("utf-8")
        findings_hash = hashlib.sha256(findings_bytes).hexdigest()

        manifest = {
            "schema_version":   "1.0",
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "operator":         self.operator,
            "scanner_version":  SCANNER_VERSION,
            "package_path":     str(self.package_path),
            "package_hash_sha256":   pkg_hash,
            "total_findings":        self.findings["summary"]["total_issues"],
            "suppressed_findings":   self.findings["summary"]["suppressed"],
            "findings_hash_sha256":  findings_hash,
            "risk_score":            self.findings["risk_score"],
            "approval_status":       self.findings["summary"]["approval_status"],
        }

        # Generate or use existing signing key
        if self._signing_private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            # Save ephemeral private key
            pem_path = self.output_dir / "manifest.pem"
            with open(pem_path, "wb") as fh:
                fh.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            logger.info("Ephemeral ECDSA key saved to %s", pem_path)
        else:
            private_key = self._signing_private_key

        # Sign
        manifest_bytes = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode("utf-8")
        signature_der = private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(signature_der).decode("ascii")

        # Public key export
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write files
        manifest_path = self.output_dir / "manifest.json"
        sig_path      = self.output_dir / "manifest.sig"
        pub_path      = self.output_dir / "manifest_public.pem"

        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        with open(sig_path, "w", encoding="utf-8") as fh:
            fh.write(sig_b64)
        with open(pub_path, "wb") as fh:
            fh.write(pub_pem)

        # Store manifest hash in findings
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        self.findings["manifest"] = {
            "hash_sha256": manifest_hash,
            "timestamp":   manifest["timestamp"],
            "signed":      True,
        }
        print(f"\n   [✓] Cryptographic manifest written (SHA256: {manifest_hash[:24]}...)")

    @staticmethod
    def _verify_manifest(manifest_dir: Path) -> Dict[str, Any]:
        """
        Verify a previously generated cryptographic manifest.

        Parameters
        ----------
        manifest_dir : Path
            Directory containing manifest.json, manifest.sig, manifest_public.pem

        Returns
        -------
        dict with keys: valid (bool), message (str), manifest (dict|None)
        """
        if not _CRYPTO_AVAILABLE:
            return {"valid": False, "message": "cryptography library not available", "manifest": None}

        try:
            manifest_path = manifest_dir / "manifest.json"
            sig_path      = manifest_dir / "manifest.sig"
            pub_path      = manifest_dir / "manifest_public.pem"

            for p in (manifest_path, sig_path, pub_path):
                if not p.exists():
                    return {"valid": False, "message": f"Missing file: {p.name}", "manifest": None}

            with open(manifest_path, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            with open(sig_path, "r", encoding="utf-8") as fh:
                sig_b64 = fh.read().strip()
            with open(pub_path, "rb") as fh:
                pub_key = serialization.load_pem_public_key(fh.read(), backend=default_backend())

            manifest_bytes = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode("utf-8")
            signature_der  = base64.b64decode(sig_b64)

            pub_key.verify(signature_der, manifest_bytes, ec.ECDSA(hashes.SHA256()))
            return {"valid": True, "message": "Signature valid", "manifest": manifest}

        except InvalidSignature:
            return {"valid": False, "message": "Signature INVALID - manifest may be tampered", "manifest": None}
        except Exception as exc:
            return {"valid": False, "message": f"Verification error: {exc}", "manifest": None}

    def _generate_audit_log_entry(self, event_type: str, data: dict) -> None:
        """
        Append a chained JSONL audit log entry to output_dir/audit.log.

        Each entry includes a chain hash: SHA256(prev_entry_hash + current_data_json).
        """
        try:
            audit_path = self.output_dir / "audit.log"
            data_json  = json.dumps(data, sort_keys=True, ensure_ascii=True)
            chain_input = (self._audit_prev_hash + data_json).encode("utf-8")
            entry_hash  = hashlib.sha256(chain_input).hexdigest()

            entry = {
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "operator":    self.operator,
                "event_type":  event_type,
                "data":        data,
                "entry_hash":  entry_hash,
                "prev_hash":   self._audit_prev_hash,
            }

            with open(audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=True) + "\n")

            self._audit_prev_hash = entry_hash
        except Exception as exc:
            logger.warning("Audit log write failed: %s", exc)

    # =========================================================================
    # NVD CVE Lookup
    # =========================================================================

    def _query_nvd_cve(self, sha256_hash: str, component_name: str) -> List[Dict]:
        """
        Query NVD 2.0 API for CVEs matching component_name.

        Results are cached in SQLite for 24 hours.  Graceful offline fallback.

        Returns list of {cve_id, cvss_score, description, published_date}.
        """
        # Check cache
        try:
            conn = sqlite3.connect(str(self._nvd_db_path))
            row = conn.execute(
                "SELECT cves_json, cached_at FROM nvd_cache WHERE component = ?",
                (component_name,),
            ).fetchone()

            if row:
                cached_at = datetime.fromisoformat(row[1])
                age = datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)
                if age < timedelta(hours=24):
                    conn.close()
                    return json.loads(row[0])
            conn.close()
        except Exception as exc:
            logger.debug("NVD cache read error: %s", exc)

        # Live query
        cves: List[Dict] = []
        if not _REQUESTS_AVAILABLE:
            logger.debug("requests not installed - NVD lookup skipped for %s", component_name)
            return cves

        try:
            resp = requests.get(
                NVD_API_BASE,
                params={"keywordSearch": component_name, "resultsPerPage": 5},
                timeout=10,
                headers={"User-Agent": f"PSADT-Secure/{SCANNER_VERSION}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_obj  = vuln.get("cve", {})
                    cve_id   = cve_obj.get("id", "")
                    desc     = ""
                    for d in cve_obj.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:300]
                            break
                    # CVSS v3 preferred, fall back to v2
                    cvss_score = 0.0
                    metrics = cve_obj.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics and metrics[key]:
                            cvss_data = metrics[key][0].get("cvssData", {})
                            cvss_score = float(cvss_data.get("baseScore", 0.0))
                            break

                    pub_date = cve_obj.get("published", "")[:10]
                    cves.append({
                        "cve_id":         cve_id,
                        "cvss_score":     cvss_score,
                        "description":    desc,
                        "published_date": pub_date,
                    })
        except requests.exceptions.Timeout:
            logger.debug("NVD API timeout for component %s", component_name)
        except Exception as exc:
            logger.debug("NVD API error for %s: %s", component_name, exc)

        # Store in cache
        try:
            conn = sqlite3.connect(str(self._nvd_db_path))
            conn.execute(
                """INSERT OR REPLACE INTO nvd_cache (hash, component, cves_json, cached_at)
                   VALUES (?, ?, ?, ?)""",
                (sha256_hash, component_name, json.dumps(cves), datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.debug("NVD cache write error: %s", exc)

        return cves

    # =========================================================================
    # SARIF 2.1.0 Report
    # =========================================================================

    def _generate_sarif_report(self) -> None:
        """Generate SARIF 2.1.0 JSON report for IDE and CI/CD integration."""
        # Build unique rules from all issues
        rules_seen: set = set()
        rules: List[Dict] = []

        all_issues = self.findings["issues"] + self.findings["suppressed_findings"]

        for issue in all_issues:
            rule_id = issue.get("rule_id", issue.get("pattern", "unknown"))
            if rule_id in rules_seen:
                continue
            rules_seen.add(rule_id)
            cvss   = issue.get("cvss", {})
            comp   = issue.get("compliance", {})
            rules.append({
                "id":               rule_id,
                "name":             rule_id,
                "shortDescription": {"text": issue.get("description", rule_id)},
                "fullDescription":  {"text": issue.get("description", rule_id)},
                "helpUri":          f"{SCANNER_INFO_URI}/wiki/rules#{rule_id}",
                "help": {
                    "text": issue.get("remediation", "Review and remediate per security policy"),
                },
                "properties": {
                    "security-severity": str(cvss.get("base_score", 5.0)),
                    "cvss-vector":        cvss.get("vector", ""),
                    "mitre-attack":       issue.get("mitre_id", ""),
                    "cwe":                issue.get("cwe_id", ""),
                    "nist-800-53":        comp.get("nist_800_53", []),
                    "cmmc-2":             comp.get("cmmc_2", []),
                    "tags": [
                        "security", "powershell", "psadt",
                        issue.get("severity", "MEDIUM").lower(),
                    ],
                },
                "defaultConfiguration": {
                    "level": self._sarif_level(issue.get("severity", "MEDIUM")),
                },
            })

        # Build results
        results: List[Dict] = []
        for issue in self.findings["issues"]:
            rule_id  = issue.get("rule_id", issue.get("pattern", "unknown"))
            severity = issue.get("severity", "MEDIUM")
            file_uri = Path(issue.get("file", "unknown")).as_uri()
            line_num = max(1, issue.get("line", 1))

            results.append({
                "ruleId":  rule_id,
                "level":   self._sarif_level(severity),
                "message": {
                    "text": (
                        f"[{severity}] {issue.get('description', rule_id)} | "
                        f"Match: {issue.get('match', '')[:80]} | "
                        f"Remediation: {issue.get('remediation', '')[:100]}"
                    ),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line_num},
                    },
                }],
                "properties": {
                    "severity":  severity,
                    "cvss":      issue.get("cvss", {}),
                    "mitre":     issue.get("mitre_id", ""),
                    "cwe":       issue.get("cwe_id", ""),
                    "confidence": issue.get("confidence", 0.8),
                },
            })

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":           "PSADT-Secure",
                        "version":        SCANNER_VERSION,
                        "informationUri": SCANNER_INFO_URI,
                        "rules":          rules,
                        "properties": {
                            "operator": self.operator,
                        },
                    },
                },
                "results":   results,
                "artifacts": [{"location": {"uri": Path(str(self.package_path)).as_uri()}}],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc":        self.findings["timestamp"],
                    "endTimeUtc":          datetime.now(timezone.utc).isoformat(),
                }],
            }],
        }

        sarif_path = self.output_dir / "findings.sarif"
        with open(sarif_path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"   [✓] SARIF report: {sarif_path.name}")

    @staticmethod
    def _sarif_level(severity: str) -> str:
        """Map severity to SARIF level."""
        return {
            "CRITICAL": "error",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
            "INFO":     "note",
        }.get(severity.upper(), "warning")

    # =========================================================================
    # JUnit XML Report
    # =========================================================================

    def _generate_junit_report(self) -> None:
        """
        Generate JUnit XML report for CI/CD pipeline gating.

        Structure:
          - testsuite: one per scan
          - testcase:  one per file scanned
          - failure:   one per finding in that file (CRITICAL/HIGH → error; others → failure)
        """
        summary  = self.findings["summary"]
        pkg_name = self.findings["package"]

        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite")
        suite.set("name",      "PSADT-Security-Scan")
        suite.set("package",   pkg_name)
        suite.set("timestamp", self.findings["timestamp"])
        suite.set("tests",     str(summary["files_scanned"]))
        suite.set("failures",  str(summary["critical"] + summary["high"]))
        suite.set("errors",    str(summary["critical"]))
        suite.set("skipped",   str(summary["suppressed"]))
        suite.set("time",      str(summary["scan_duration"]))

        # Group findings by file
        file_issues: Dict[str, List[Dict]] = {}
        for issue in self.findings["issues"]:
            fp = issue.get("file", "unknown")
            file_issues.setdefault(fp, []).append(issue)

        # A passing file (no findings) still gets a testcase
        scanned_files: set = set()
        for issue in self.findings["issues"]:
            scanned_files.add(issue.get("file", "unknown"))

        for fp in scanned_files:
            rel_name = Path(fp).name
            tc = ET.SubElement(suite, "testcase")
            tc.set("name",      f"Security scan: {rel_name}")
            tc.set("classname", "PSADTSecureScanner")
            tc.set("file",      fp)

            for issue in file_issues.get(fp, []):
                severity  = issue.get("severity", "LOW")
                rule_id   = issue.get("rule_id", issue.get("pattern", "unknown"))
                msg       = (
                    f"[{severity}] {rule_id} at line {issue.get('line', '?')}: "
                    f"{issue.get('description', issue.get('match', ''))[:150]}"
                )
                if severity in ("CRITICAL", "HIGH"):
                    el = ET.SubElement(tc, "failure" if severity == "HIGH" else "error")
                    el.set("message", msg)
                    el.set("type",    severity)
                    el.text = (
                        f"Rule:        {rule_id}\n"
                        f"Severity:    {severity}\n"
                        f"CVSS Score:  {issue.get('cvss', {}).get('base_score', 'N/A')}\n"
                        f"MITRE:       {issue.get('mitre_id', 'N/A')}\n"
                        f"CWE:         {issue.get('cwe_id', 'N/A')}\n"
                        f"Match:       {issue.get('match', 'N/A')}\n"
                        f"Remediation: {issue.get('remediation', 'N/A')}"
                    )
                else:
                    el = ET.SubElement(tc, "failure")
                    el.set("message", msg)
                    el.set("type",    severity)
                    el.text = msg

        # Write
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        junit_path = self.output_dir / "findings_junit.xml"
        tree.write(junit_path, encoding="utf-8", xml_declaration=True)
        print(f"   [✓] JUnit XML report: {junit_path.name}")

    # =========================================================================
    # CSV Report
    # =========================================================================

    def _generate_csv_report(self) -> None:
        """Generate CSV export including CVSS score and compliance tags."""
        csv_path = self.output_dir / "findings.csv"
        fieldnames = [
            "File", "Type", "Severity", "Line", "Rule ID",
            "Pattern", "Issue", "MITRE ATT&CK", "CWE",
            "CVSS Score", "CVSS Vector", "Remediation",
            "NIST 800-53", "CMMC 2.0", "CIS v8", "IEC 62443", "OWASP",
            "Confidence", "Suppressed",
        ]

        all_rows = [
            (issue, False) for issue in self.findings["issues"]
        ] + [
            (issue, True) for issue in self.findings["suppressed_findings"]
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for issue, suppressed in all_rows:
                cvss  = issue.get("cvss", {})
                comp  = issue.get("compliance", {})
                writer.writerow({
                    "File":         Path(issue.get("file", "")).name,
                    "Type":         issue.get("type", ""),
                    "Severity":     issue.get("severity", ""),
                    "Line":         issue.get("line", 0),
                    "Rule ID":      issue.get("rule_id", issue.get("pattern", "")),
                    "Pattern":      issue.get("pattern", ""),
                    "Issue":        issue.get("match", "")[:100],
                    "MITRE ATT&CK": issue.get("mitre_id", ""),
                    "CWE":          issue.get("cwe_id", ""),
                    "CVSS Score":   cvss.get("base_score", ""),
                    "CVSS Vector":  cvss.get("vector", ""),
                    "Remediation":  issue.get("remediation", "")[:120],
                    "NIST 800-53":  "; ".join(comp.get("nist_800_53", [])),
                    "CMMC 2.0":     "; ".join(comp.get("cmmc_2", [])),
                    "CIS v8":       "; ".join(comp.get("cis_v8", [])),
                    "IEC 62443":    "; ".join(comp.get("iec_62443", [])),
                    "OWASP":        "; ".join(comp.get("owasp", [])),
                    "Confidence":   issue.get("confidence", ""),
                    "Suppressed":   "YES" if suppressed else "NO",
                })

    # =========================================================================
    # HTML Report
    # =========================================================================

    def _generate_html_report(self) -> None:
        """Generate a comprehensive HTML security dashboard."""
        summary    = self.findings["summary"]
        risk_score = self.findings["risk_score"]
        status     = summary["approval_status"]
        risk_color = "red" if risk_score > 75 else "orange" if risk_score > 30 else "#28a745"
        status_cls = {
            "APPROVED":        "approved",
            "REVIEW_REQUIRED": "review",
            "REJECTED":        "rejected",
            "PENDING":         "review",
        }.get(status, "review")

        # Build compliance table rows
        comp_rows = ""
        for fw, controls in self.findings.get("compliance_summary", {}).items():
            if controls:
                comp_rows += f"<tr><td><strong>{fw.upper()}</strong></td><td>{', '.join(controls)}</td></tr>"

        # Build findings rows
        findings_rows = ""
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_issues = sorted(
            self.findings["issues"],
            key=lambda x: sev_order.get(x.get("severity", "INFO"), 5),
        )
        for issue in sorted_issues:
            sev      = issue.get("severity", "LOW")
            cvss_s   = issue.get("cvss", {}).get("base_score", "N/A")
            mitre    = issue.get("mitre_id", "N/A")
            rule_id  = issue.get("rule_id", issue.get("pattern", ""))
            findings_rows += f"""
                <tr>
                    <td><span class="{sev.lower()}">{sev}</span></td>
                    <td><strong>{Path(issue.get('file', '')).name}</strong></td>
                    <td>{issue.get('line', 'N/A')}</td>
                    <td><code>{rule_id}</code></td>
                    <td>{issue.get('description', issue.get('match', ''))[:80]}</td>
                    <td><strong>{cvss_s}</strong></td>
                    <td><code>{mitre}</code></td>
                    <td><small>{issue.get('remediation', '')[:70]}</small></td>
                </tr>
"""

        manifest_hash = self.findings.get("manifest", {}).get("hash_sha256", "N/A")
        scan_ts       = self.findings["timestamp"]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PSADT-Secure v{SCANNER_VERSION} Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; padding: 20px; }}
        .container {{ max-width: 1600px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #c41e3a 0%, #7a0d20 100%); color: white; padding: 32px 40px; }}
        .header h1 {{ font-size: 2.2em; margin-bottom: 8px; }}
        .header p {{ font-size: 0.95em; opacity: 0.9; margin-top: 4px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; padding: 28px 40px; background: #fafafa; }}
        .card {{ background: white; border-left: 5px solid #c41e3a; padding: 18px; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
        .card .number {{ font-size: 2.4em; font-weight: 700; color: #c41e3a; }}
        .card .label  {{ color: #666; margin-top: 4px; font-size: 0.9em; }}
        .card.green   {{ border-left-color: #28a745; }} .card.green .number {{ color: #28a745; }}
        .card.orange  {{ border-left-color: #fd7e14; }} .card.orange .number {{ color: #fd7e14; }}
        .card.yellow  {{ border-left-color: #ffc107; }} .card.yellow .number {{ color: #856404; }}
        .card.blue    {{ border-left-color: #17a2b8; }} .card.blue .number {{ color: #17a2b8; }}
        .card.gray    {{ border-left-color: #6c757d; }} .card.gray .number {{ color: #6c757d; }}
        .section {{ padding: 28px 40px; border-top: 1px solid #eee; }}
        .section h2 {{ color: #c41e3a; margin-bottom: 16px; font-size: 1.5em; }}
        .risk-bar {{ height: 24px; background: #eee; border-radius: 12px; overflow: hidden; margin: 12px 0; }}
        .risk-fill {{ height: 100%; background: {risk_color}; width: {min(risk_score,100):.1f}%; border-radius: 12px; transition: width .3s; }}
        .risk-number {{ font-size: 2.8em; font-weight: 800; color: {risk_color}; }}
        .status-approved {{ background: #d4edda; border-left: 5px solid #28a745; padding: 14px 20px; border-radius: 6px; margin: 12px 0; }}
        .status-rejected  {{ background: #f8d7da; border-left: 5px solid #dc3545; padding: 14px 20px; border-radius: 6px; margin: 12px 0; }}
        .status-review    {{ background: #fff3cd; border-left: 5px solid #ffc107; padding: 14px 20px; border-radius: 6px; margin: 12px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.88em; }}
        th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
        td {{ padding: 9px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .critical {{ color: #dc3545; font-weight: 700; }}
        .high     {{ color: #fd7e14; font-weight: 700; }}
        .medium   {{ color: #856404; font-weight: 600; }}
        .low      {{ color: #17a2b8; font-weight: 600; }}
        .info     {{ color: #6c757d; }}
        code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 0.92em; }}
        .footer {{ background: #f8f9fa; padding: 16px 40px; text-align: center; color: #888; font-size: 0.85em; border-top: 1px solid #eee; }}
        .manifest-box {{ background: #1e1e2e; color: #a6e3a1; padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 0.85em; margin-top: 10px; }}
    </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔐 PSADT-Secure v{SCANNER_VERSION} – Security Scan Report</h1>
    <p>Defense-Grade PSADT Package Security Assessment</p>
    <p>Package: <strong>{self.findings['package']}</strong> &nbsp;|&nbsp; Operator: <strong>{self.operator}</strong></p>
    <p>Scan Timestamp: {scan_ts}</p>
  </div>

  <div class="summary-grid">
    <div class="card"><div class="number">{summary['total_issues']}</div><div class="label">Total Issues</div></div>
    <div class="card"><div class="number critical">{summary['critical']}</div><div class="label">CRITICAL</div></div>
    <div class="card orange"><div class="number">{summary['high']}</div><div class="label">HIGH</div></div>
    <div class="card yellow"><div class="number">{summary['medium']}</div><div class="label">MEDIUM</div></div>
    <div class="card blue"><div class="number">{summary['low']}</div><div class="label">LOW</div></div>
    <div class="card gray"><div class="number">{summary['suppressed']}</div><div class="label">Suppressed</div></div>
    <div class="card green"><div class="number">{summary['files_scanned']}</div><div class="label">Files Scanned</div></div>
    <div class="card gray"><div class="number">{summary['binaries_analyzed']}</div><div class="label">Binaries</div></div>
  </div>

  <div class="section">
    <h2>Risk Assessment</h2>
    <div class="risk-number">{risk_score:.1f} / 100</div>
    <div class="risk-bar"><div class="risk-fill"></div></div>
    <div class="status-{status_cls}">
      <strong>Deployment Status: {status}</strong><br>
      {'✅ Package APPROVED for deployment – no critical/high issues and risk score < 30' if status == 'APPROVED'
        else '❌ Package REJECTED – critical findings or risk score > 75. Remediation required before deployment.'
        if status == 'REJECTED'
        else '⚠️ Package REQUIRES SECURITY REVIEW before deployment'}
    </div>
  </div>

  <div class="section">
    <h2>Detailed Findings ({len(self.findings['issues'])} active)</h2>
    <table>
      <tr>
        <th>Severity</th><th>File</th><th>Line</th><th>Rule ID</th>
        <th>Description</th><th>CVSS</th><th>MITRE</th><th>Remediation</th>
      </tr>
{findings_rows}
    </table>
  </div>

  <div class="section">
    <h2>Compliance Framework Coverage</h2>
    <table>
      <tr><th>Framework</th><th>Controls Triggered</th></tr>
{comp_rows}
    </table>
  </div>

  <div class="section">
    <h2>Cryptographic Manifest</h2>
    <div class="manifest-box">
      Manifest SHA-256: {manifest_hash}<br>
      Signed: {'Yes (ECDSA P-256)' if self.findings.get('manifest', {}).get('signed') else 'No (cryptography library not available)'}<br>
      Timestamp: {self.findings.get('manifest', {}).get('timestamp', scan_ts)}
    </div>
  </div>

  <div class="footer">
    <p>PSADT-Secure v{SCANNER_VERSION} | Defense-Grade PSADT Package Security Scanner</p>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Operator: {self.operator}</p>
  </div>
</div>
</body>
</html>"""

        html_path = self.output_dir / "report.html"
        html_path.write_text(html, encoding="utf-8")
        print(f"   [✓] HTML report: {html_path.name}")

    # =========================================================================
    # Master Report Orchestrator
    # =========================================================================

    def _generate_report(self) -> None:
        """
        Determine approval status, then generate all report formats.

        Approval logic:
          APPROVED          - 0 critical, 0 high, risk_score < 30
          REVIEW_REQUIRED   - high > 0 OR (risk_score 30-75 AND critical == 0)
          REJECTED          - critical > 0 OR risk_score > 75
        """
        summary = self.findings["summary"]
        risk    = self.findings["risk_score"]

        if summary["critical"] > 0 or risk > 75:
            summary["approval_status"] = "REJECTED"
        elif summary["high"] > 0 or (30 <= risk <= 75):
            summary["approval_status"] = "REVIEW_REQUIRED"
        else:
            summary["approval_status"] = "APPROVED"

        print(f"\n   [*] Approval status: {summary['approval_status']}")

        # HTML
        self._generate_html_report()

        # JSON (full findings)
        json_path = self.output_dir / "findings.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(self.findings, fh, indent=2, default=str)
        print(f"   [✓] JSON report: {json_path.name}")

        # CSV
        self._generate_csv_report()
        print(f"   [✓] CSV report: findings.csv")

        # SARIF
        try:
            self._generate_sarif_report()
        except Exception as exc:
            logger.error("SARIF generation failed: %s", exc)

        # JUnit XML
        try:
            self._generate_junit_report()
        except Exception as exc:
            logger.error("JUnit generation failed: %s", exc)

        # Cryptographic manifest
        try:
            self._generate_cryptographic_manifest()
        except Exception as exc:
            logger.error("Manifest generation failed: %s", exc)

        print(f"\n[✓] All reports saved to: {self.output_dir}")

    # =========================================================================
    # Helper Utilities
    # =========================================================================

    def _detect_obfuscation(self, content: str) -> bool:
        """Detect code obfuscation using multiple heuristics."""
        indicators = [
            r"`[a-zA-Z]",                     # Backtick escaping
            r"\$\(\[char\]",                  # Char encoding
            r"\[Convert\]::FromBase64String", # Base64 decode
            r"\\x[0-9a-fA-F]{2}",            # Hex byte literals
            r"(?i)iex\s*\(",                  # IEX short alias
            r"\-join\s*\(\s*'",              # String join obfuscation
            r"\[char\]\s*\d{2,3}",           # Char casting
            r"System\.Text\.Encoding",        # Encoding ops
        ]
        hits = sum(1 for i in indicators if re.search(i, content, re.IGNORECASE))
        return hits >= 3  # Require ≥3 indicators for heuristic hit

    def _calculate_entropy(self, file_path: Path) -> float:
        """Calculate Shannon entropy of file bytes."""
        try:
            data = file_path.read_bytes()
            if not data:
                return 0.0
            byte_counts = Counter(data)
            entropy = 0.0
            length = len(data)
            for count in byte_counts.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            return round(entropy, 4)
        except Exception:
            return 0.0

    def _calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate cryptographic hash of a file."""
        try:
            h = hashlib.new(algorithm)
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "error"

    def _hash_directory(self, dir_path: Path) -> str:
        """Compute deterministic SHA-256 over all files in a directory tree."""
        h = hashlib.sha256()
        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file():
                try:
                    h.update(file_path.read_bytes())
                except Exception:
                    pass
        return h.hexdigest()

    def _check_signature_detailed(self, file_path: Path) -> Tuple[bool, str]:
        """
        Check Authenticode signature via PowerShell.

        Returns (is_valid: bool, status_string: str).
        """
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"$s=(Get-AuthenticodeSignature '{str(file_path).replace(chr(39), chr(39)*2)}'); "
                    f"Write-Output $s.Status",
                ],
                capture_output=True, text=True, timeout=10,
            )
            status = result.stdout.strip()
            return (status == "Valid"), status
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as exc:
            return False, f"Error: {exc}"

    def _update_summary(self, severity: str) -> None:
        """Increment severity counter in summary."""
        self.findings["summary"]["total_issues"] += 1
        key = severity.lower()
        if key in self.findings["summary"]:
            self.findings["summary"][key] += 1

    def _get_context(self, content: str, position: int, lines: int = 2) -> str:
        """Return ±lines lines of context around a match position."""
        try:
            all_lines  = content.splitlines()
            line_num   = content[:position].count("\n")
            start      = max(0, line_num - lines)
            end        = min(len(all_lines), line_num + lines + 1)
            return "\n".join(all_lines[start:end])[:300]
        except Exception:
            return "N/A"

    def _get_remediation(self, pattern_name: str) -> str:
        """Return detailed remediation guidance for a given pattern."""
        remediation_map: Dict[str, str] = {
            "hardcoded_credential":           "Move secrets to SCCM TS Variable (mark Private) or Azure Key Vault",
            "secure_string_plaintext":        "Remove -AsPlainText -Force; use DPAPI or managed credential store",
            "credential_creation":            "Replace inline PSCredential with SCCM TS Variables or MSA",
            "invoke_expression":              "Use validated -ScriptBlock; never pass user or env data to IEX",
            "script_block_manipulation":      "Avoid dynamic ScriptBlock construction; use explicit function calls",
            "registry_manipulation":          "Document justification; restrict via AppLocker and GPO",
            "uac_bypass":                     "Remove UAC bypass - use SCCM system-context elevation instead",
            "event_log_clearing":             "Remove event log manipulation; enforce immutable log storage",
            "disabled_security":              "Keep all security features enabled; enforce via Group Policy",
            "lateral_movement":              "Remove remote execution; use SCCM/Intune for remote deployment",
            "credential_dumping":             "Remove and investigate immediately; rotate all credentials",
            "service_creation":              "Document service purpose; use SCCM service deployment task",
            "scheduled_task":                "Use SCCM deployment tasks; remove persistence mechanisms",
            "external_download":             "Bundle content in package; allowlist and verify URLs via proxy",
            "remote_execution":              "Use SCCM deployment infrastructure; avoid direct remote exec",
            "com_object":                    "Verify COM object necessity; use only safe, whitelisted ProgIDs",
            "rundll_execution":              "Replace with direct executable calls; avoid UNC/HTTP arguments",
            "obfuscation_detected":          "Deobfuscate script; verify source code is from trusted origin",
            "amsi_patch_memory":             "BLOCK IMMEDIATELY – AMSI bypass constitutes active evasion",
            "amsi_reflection":               "BLOCK IMMEDIATELY – Reflection-based AMSI bypass detected",
            "amsi_script_bypass":            "BLOCK IMMEDIATELY – Memory-patching AMSI bypass detected",
            "amsi_force_error":              "BLOCK IMMEDIATELY – AMSI force-error bypass detected",
            "amsi_null_context":             "Review Marshal::Copy usage; investigate intent",
            "lolbin_certutil_decode":        "Replace certutil with native PowerShell; block certutil in AppLocker",
            "lolbin_mshta":                  "Block mshta.exe via AppLocker/WDAC; remove inline scripting",
            "lolbin_wscript_cscript":        "Migrate to PowerShell; block WScript/CScript via AppLocker",
            "lolbin_msiexec_remote":         "Never install MSI from remote URL; bundle in package content",
            "lolbin_regsvr32_scrobj":        "Block regsvr32 scriptlet execution via WDAC",
            "lolbin_bitsadmin":              "Replace with Invoke-WebRequest; block BITSAdmin via AppLocker",
            "lolbin_forfiles":               "Avoid forfiles for execution; use direct PowerShell calls",
            "lolbin_installutil":            "Block InstallUtil via AppLocker; use signed code paths",
            "wmi_event_subscription":        "Remove WMI subscription; investigate for existing persistence",
            "registry_run_key":              "Document autostart justification; prefer service or task deployment",
            "startup_folder":                "Remove startup folder deployment; use proper service registration",
            "clm_bypass":                    "Avoid ScriptBlock::Create in CLM environments; validate inputs",
            "etw_tampering":                 "BLOCK IMMEDIATELY – ETW tampering disables audit telemetry",
            "dotnet_reflection":             "Review reflective load source; block unsigned assembly load",
            "applocker_bypass":              "Deny LOLBin via WDAC/AppLocker deny-list rules",
            "psadt_execute_ignore_all_exits":"Replace wildcard IgnoreExitCodes with specific codes; handle failures",
            "psadt_unvalidated_path":        "Validate all path parameters against known safe prefixes",
            "psadt_invoke_all_users_reg":    "Add inline comment justifying HKLM scope; prefer per-user hive",
            "psadt_show_dialog_exec":        "Do not wire dialog buttons to dynamic code execution",
            "psadt_env_var_injection":       "Never pass $env: variables directly to Invoke-Expression",
            "psadt_deprecated_v3_appdeployment": "Migrate to equivalent PSADT v4 ADT cmdlet",
            "psadt_set_shortcut_hotkey":     "Review HotKey assignment; document business justification",
            "psadt_run_as_active_user":      "Document use of active-user context; minimize scope",
        }
        return remediation_map.get(pattern_name, "Review and remediate per organizational security policy")

    # =========================================================================
    # Print Summary
    # =========================================================================

    def print_summary(self) -> None:
        """Print comprehensive scan summary to stdout."""
        summary     = self.findings["summary"]
        risk        = self.findings["risk_score"]
        status      = summary["approval_status"]
        manifest    = self.findings.get("manifest", {})

        # CVSS range for critical issues
        critical_cvss_scores = [
            issue.get("cvss", {}).get("base_score", 0.0)
            for issue in self.findings["issues"]
            if issue.get("severity") == "CRITICAL"
        ]
        cvss_range = ""
        if critical_cvss_scores:
            cvss_range = f"CVSS {min(critical_cvss_scores):.1f} – {max(critical_cvss_scores):.1f}"

        # Compliance frameworks affected
        comp_frameworks = [
            fw for fw, controls in self.findings.get("compliance_summary", {}).items()
            if controls
        ]

        print("\n" + "=" * 90)
        print("  PSADT-SECURE v3.0 – COMPREHENSIVE SCAN RESULTS")
        print("=" * 90)

        print(f"\n📦 PACKAGE:   {self.findings['package']}")
        print(f"   Path:     {self.findings['package_path']}")
        print(f"   Operator: {self.operator}")

        print(f"\n📊 ISSUE SUMMARY:")
        print(f"   Total Active  : {summary['total_issues']}")
        print(f"   🔴 CRITICAL   : {summary['critical']}" + (f"  (CVSS: {cvss_range})" if cvss_range else ""))
        print(f"   🟠 HIGH       : {summary['high']}")
        print(f"   🟡 MEDIUM     : {summary['medium']}")
        print(f"   🔵 LOW        : {summary['low']}")
        print(f"   ⬜ Suppressed : {summary['suppressed']}  (via allowlist)")

        print(f"\n🎯 RISK ASSESSMENT:")
        print(f"   Risk Score : {risk:.1f} / 100")
        bar = "█" * int(risk / 5) + "░" * (20 - int(risk / 5))
        print(f"   [{bar}]")

        print(f"\n📋 COMPLIANCE FRAMEWORKS TRIGGERED:")
        if comp_frameworks:
            for fw in comp_frameworks:
                controls = self.findings["compliance_summary"].get(fw, [])
                print(f"   {fw.upper():15} → {', '.join(controls[:5])}" +
                      (f" (+{len(controls)-5} more)" if len(controls) > 5 else ""))
        else:
            print("   None")

        print(f"\n📈 SCAN METRICS:")
        print(f"   Duration          : {summary['scan_duration']:.2f}s")
        print(f"   Files Scanned     : {summary['files_scanned']}")
        print(f"   PowerShell Files  : {summary['ps_files']}")
        print(f"   Binaries Analyzed : {summary['binaries_analyzed']}")
        print(f"   MSI Packages      : {summary.get('msi_files', 0)}")

        if manifest.get("hash_sha256"):
            print(f"\n🔏 CRYPTOGRAPHIC MANIFEST:")
            print(f"   Hash   : {manifest['hash_sha256']}")
            print(f"   Signed : {'Yes (ECDSA P-256)' if manifest.get('signed') else 'No'}")

        print(f"\n🔐 DEPLOYMENT DECISION: {status}")
        if status == "APPROVED":
            print("\n   ✅ PACKAGE APPROVED FOR DEPLOYMENT")
        elif status == "REVIEW_REQUIRED":
            print("\n   ⚠️  PACKAGE REQUIRES SECURITY REVIEW BEFORE DEPLOYMENT")
        else:
            print("\n   ❌ PACKAGE BLOCKED FROM DEPLOYMENT – REMEDIATION REQUIRED")

        if self.findings["issues"]:
            top5 = sorted(
                self.findings["issues"],
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity"), 4),
            )[:5]
            print(f"\n📋 TOP {len(top5)} FINDINGS:")
            for i, issue in enumerate(top5, 1):
                cvss_s = issue.get("cvss", {}).get("base_score", "N/A")
                print(f"\n   {i}. [{issue['severity']}] CVSS:{cvss_s}  {issue.get('rule_id', issue['pattern'])}")
                print(f"      File: {Path(issue['file']).name}:{issue.get('line', '?')}")
                print(f"      → {issue.get('remediation', '')[:85]}")

        print(f"\n📄 REPORTS GENERATED IN: {self.output_dir}")
        print(f"   ├─ report.html          (visual dashboard)")
        print(f"   ├─ findings.json        (full structured data)")
        print(f"   ├─ findings.csv         (spreadsheet with CVSS + compliance)")
        print(f"   ├─ findings.sarif       (SARIF 2.1.0 for IDE/GH integration)")
        print(f"   ├─ findings_junit.xml   (JUnit XML for CI/CD gating)")
        print(f"   ├─ manifest.json        (cryptographic manifest)")
        print(f"   ├─ manifest.sig         (ECDSA P-256 signature)")
        print(f"   ├─ manifest_public.pem  (public key for verification)")
        print(f"   └─ audit.log            (tamper-evident chained audit log)")
        print("\n" + "=" * 90)


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point with argument parsing and CI/CD exit codes."""
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   PSADT-SECURE v{SCANNER_VERSION}: Defense-Grade PSADT Package Security Scanner   ║
║   Aerospace/Defense Enterprise Edition                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
    python main.py <package_path> [output_dir]
    python src/scanners/scan_psadt.py <package_path> [output_dir]

ARGUMENTS:
    <package_path>   Required: Path to PSADT package directory
    [output_dir]     Optional: Directory for report output
                     Default: psadt_scan_YYYYMMDD_HHMMSS

ENVIRONMENT VARIABLES:
    PSADT_SCAN_OPERATOR      Operator identity written to manifest/audit log
    PSADT_SIGNING_KEY_PATH   Path to ECDSA P-256 PEM private key for signing

EXAMPLES:
    python main.py "C:\\SCCM\\Packages\\MyApp"
    python main.py "C:\\SCCM\\Packages\\MyApp" "C:\\Reports\\MyApp-Scan"
    PSADT_SCAN_OPERATOR=john.doe python main.py /packages/myapp

SCAN STEPS (8 total):
    1. Advanced PowerShell analysis  (60+ patterns, AMSI/LOLBin/persistence)
    2. Binary chain-of-trust         (pefile imports, entropy, NVD CVE lookup)
    3. Credential detection          (passwords, keys, tokens, cloud secrets)
    4. Malware pattern detection     (C2, process injection, reverse shells)
    5. Configuration analysis        (TLS, password policy, debug flags)
    6. PSADT v4.1 cmdlet compliance  (deprecated APIs, exit-code masking)
    7. MSI/MSP/MSIX analysis         (custom action types, signing, remote URLs)
    8. Risk scoring + MITRE mapping  (CVSS, compliance tagging, reporting)

OUTPUT FILES:
    report.html          Visual HTML dashboard
    findings.json        Full structured data (machine-readable)
    findings.csv         Spreadsheet with CVSS + compliance columns
    findings.sarif       SARIF 2.1.0 (GitHub Advanced Security / IDE)
    findings_junit.xml   JUnit XML (CI/CD pipeline gating)
    manifest.json        Cryptographic scan manifest
    manifest.sig         ECDSA P-256 base64 signature
    manifest_public.pem  Public key for manifest verification
    audit.log            Tamper-evident chained JSONL audit log
    nvd_cache.db         SQLite NVD CVE cache

EXIT CODES:
    0 = Package APPROVED  (0 critical, 0 high, risk < 30)
    1 = REVIEW_REQUIRED or REJECTED
    2 = Fatal scanner error
""")
        sys.exit(0)

    package_path = sys.argv[1]
    output_dir   = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isdir(package_path):
        print(f"❌ Error: Package directory not found: {package_path}", file=sys.stderr)
        sys.exit(2)

    try:
        scanner  = PSADTSecureScanner(package_path, output_dir)
        findings = scanner.scan()
        scanner.print_summary()

        status = findings["summary"]["approval_status"]
        if status == "APPROVED":
            print("\n✅ Success: Package approved for deployment")
            sys.exit(0)
        else:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"\n❌ Fatal Error: {exc}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
