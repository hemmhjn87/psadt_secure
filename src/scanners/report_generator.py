#!/usr/bin/env python3
"""
HemSpect Enterprise HTML Report Generator v3.0
Produces single-page application reports for aerospace/defense security reviews.
Design: Deep navy (#0a1628) / gold (#f0a500) / white – Boeing/Safran compliant.
"""

import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

SCANNER_VERSION = "3.0"

# Severity sort order
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# MITRE ATT&CK tactic columns (all 14)
ATTACK_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# Technique-ID → Tactic mapping (abbreviated; covers all rules in scan_psadt.py)
TECHNIQUE_TACTIC_MAP: Dict[str, str] = {
    "T1059": "Execution",
    "T1086": "Execution",
    "T1106": "Execution",
    "T1173": "Execution",
    "T1105": "Command and Control",
    "T1001": "Command and Control",
    "T1112": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1085": "Defense Evasion",
    "T1088": "Privilege Escalation",
    "T1021": "Lateral Movement",
    "T1050": "Persistence",
    "T1053": "Persistence",
    "T1087": "Credential Access",
    "T1003": "Credential Access",
    "T1110": "Credential Access",
    "T1552": "Credential Access",
    "T1078": "Initial Access",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1089": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1028": "Lateral Movement",
}

# Compliance matrix: control_id → display labels
NIST_CONTROLS = ["SI-3", "SI-7", "CM-7", "AC-6", "AU-9", "SA-11"]
CMMC_CONTROLS = ["SI.1.210", "SI.2.214", "AU.2.041", "CM.2.061"]
CIS_CONTROLS  = ["CIS-2", "CIS-7", "CIS-10", "CIS-13"]

# Which rule IDs trigger which controls
CONTROL_TRIGGERS: Dict[str, List[str]] = {
    "SI-3":     ["invoke_expression", "script_block_manipulation", "disabled_security",
                 "amsi_patch_memory", "lolbin_certutil_decode"],
    "SI-7":     ["event_log_clearing", "amsi_patch_memory", "hardcoded_credential"],
    "CM-7":     ["registry_manipulation", "external_download", "wmi_event_subscription",
                 "remote_execution", "lolbin_certutil_decode"],
    "AC-6":     ["uac_bypass", "lateral_movement", "credential_dumping"],
    "AU-9":     ["event_log_clearing", "etw_tampering"],
    "SA-11":    ["hardcoded_credential", "invoke_expression", "script_block_manipulation"],
    "SI.1.210": ["invoke_expression", "disabled_security", "amsi_patch_memory"],
    "SI.2.214": ["amsi_patch_memory", "amsi_reflection", "script_block_manipulation"],
    "AU.2.041": ["event_log_clearing", "registry_manipulation", "wmi_event_subscription"],
    "CM.2.061": ["registry_manipulation", "external_download", "lateral_movement"],
    "CIS-2":    ["invoke_expression", "script_block_manipulation", "dotnet_reflection"],
    "CIS-7":    ["invoke_expression", "external_download", "lolbin_certutil_decode"],
    "CIS-10":   ["disabled_security", "amsi_patch_memory"],
    "CIS-13":   ["lateral_movement", "external_download", "data_exfiltration"],
}


class ReportGenerator:
    """Generates a premium single-page enterprise HTML security report."""

    def __init__(
        self,
        findings: dict,
        sbom_data: Optional[dict] = None,
        workflow: Optional[dict] = None,
    ):
        self.findings = findings
        self.sbom_data = sbom_data or {}
        self.workflow  = workflow or {}
        self._issues   = findings.get("issues", [])
        self._summary  = findings.get("summary", {})
        self._risk_score = float(findings.get("risk_score", 0.0))

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def generate_html(self, output_path: Path):
        """Render and write the full enterprise HTML report."""
        output_path = Path(output_path)
        html = self._render()
        output_path.write_text(html, encoding="utf-8", errors="ignore")
        logger.info("HTML report written to %s", output_path)

    # ------------------------------------------------------------------ #
    #  Top-level renderer                                                  #
    # ------------------------------------------------------------------ #

    def _render(self) -> str:
        approval  = self._summary.get("approval_status", "REVIEW_REQUIRED")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        pkg_name  = self.findings.get("package", "Unknown Package")
        operator  = self.findings.get("operator", "Unknown")
        report_hash = self._report_hash()

        # Build all sections
        sec_exec      = self._section_exec_summary()
        sec_pwdintel  = self._section_password_intelligence()
        sec_risk      = self._section_risk_assessment()
        sec_compliance= self._section_compliance_matrix()
        sec_hemspect  = self._section_hemspect()
        sec_findings  = self._section_findings_explorer()
        sec_mitre     = self._section_mitre_heatmap()
        sec_sbom      = self._section_sbom()
        sec_workflow  = self._section_workflow()
        sec_audit     = self._section_audit_trail()
        sec_remediation = self._section_remediation_tracker()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HemSpect v{SCANNER_VERSION} — Security Report: {pkg_name}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  {self._css()}
</head>
<body>
  {self._status_banner(approval)}
  <div class="app-layout">
    {self._sidebar()}
    <main class="main-content" id="main-content">
      <div class="report-header">
        <div class="header-left">
          <div class="hemspect-logo-main">⚡ HemSpect<span>™</span></div>
          <div>
            <h1 class="report-title">PACKAGE SECURITY SCANNER</h1>
          </div>
        </div>
        <div class="header-right">
          <div class="meta-pill"><span class="meta-label">Package</span><span class="meta-value">{pkg_name}</span></div>
          <div class="meta-pill"><span class="meta-label">Generated</span><span class="meta-value">{timestamp}</span></div>
          <div class="meta-pill"><span class="meta-label">Operator</span><span class="meta-value">{operator}</span></div>
        </div>
      </div>

      <section id="sec-executive" class="report-section">
        <h2 class="section-title"><span class="section-icon">📊</span> Executive Summary</h2>
        {sec_exec}
      </section>

      <section id="sec-pwdintel" class="report-section">
        <h2 class="section-title"><span class="section-icon">🔑</span> Password Intelligence</h2>
        {sec_pwdintel}
      </section>

      <section id="sec-risk" class="report-section">
        <h2 class="section-title"><span class="section-icon">🎯</span> Risk Assessment</h2>
        {sec_risk}
      </section>

      <section id="sec-compliance" class="report-section">
        <h2 class="section-title"><span class="section-icon">📋</span> Compliance Matrix</h2>
        {sec_compliance}
      </section>

      <section id="sec-hemspect" class="report-section">
        <h2 class="section-title"><span class="section-icon">⚡</span> HemSpect™ Data Leakage</h2>
        {sec_hemspect}
      </section>

      <section id="sec-findings" class="report-section">
        <h2 class="section-title"><span class="section-icon">🔍</span> Other Security Findings</h2>
        {sec_findings}
      </section>

      <section id="sec-mitre" class="report-section">
        <h2 class="section-title"><span class="section-icon">🗺</span> MITRE ATT&amp;CK Heatmap</h2>
        {sec_mitre}
      </section>

      <section id="sec-sbom" class="report-section">
        <h2 class="section-title"><span class="section-icon">📦</span> SBOM Inventory</h2>
        {sec_sbom}
      </section>

      <section id="sec-workflow" class="report-section">
        <h2 class="section-title"><span class="section-icon">✅</span> Approval Workflow Status</h2>
        {sec_workflow}
      </section>

      <section id="sec-audit" class="report-section">
        <h2 class="section-title"><span class="section-icon">🕵</span> Audit Trail</h2>
        {sec_audit}
      </section>

      <section id="sec-remediation" class="report-section">
        <h2 class="section-title"><span class="section-icon">🔧</span> Remediation Tracker</h2>
        {sec_remediation}
      </section>

      <footer class="report-footer">
        <div class="footer-row">
          <span>HemSpect v{SCANNER_VERSION}</span>
          <span>Report Hash: <code>{report_hash[:32]}…</code></span>
          <span>Operator: {operator}</span>
          <span>{timestamp}</span>
        </div>
        <div class="footer-compliance">
          NIST SP 800-53 Rev5 &nbsp;|&nbsp; CMMC 2.0 &nbsp;|&nbsp;
          IEC 62443-2-4 &nbsp;|&nbsp; CIS Controls v8
        </div>
        <div style="margin-top: 18px; text-align: center; font-family: monospace; font-size: 0.85rem; color: var(--accent); padding-top: 12px; border-top: 1px dashed var(--border);">
          <span style="opacity: 0.5;">//</span> Designed by <span style="color: #6dffb9; font-weight: bold; text-shadow: 0 0 5px rgba(109,255,185,0.5);">Hem</span>
        </div>
      </footer>
    </main>
  </div>
  {self._javascript()}
</body>
</html>"""

    # ------------------------------------------------------------------ #
    #  CSS                                                                 #
    # ------------------------------------------------------------------ #

    def _css(self) -> str:
        return """<style>
:root {
  --primary:  #0a1628;
  --primary2: #0d1f3c;
  --accent:   #f0a500;
  --accent2:  #ffc233;
  --danger:   #e63946;
  --warning:  #f4a261;
  --success:  #2a9d8f;
  --info:     #4895ef;
  --surface:  #162032;
  --surface2: #1c2a42;
  --border:   #253a55;
  --text:     #e8edf5;
  --text-muted: #8ba0be;
  --sidebar-w: 240px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--primary);
  color: var(--text);
  line-height: 1.6;
  font-size: 14px;
}

/* ---- Status Banner ---- */
.status-banner {
  position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
  display: flex; align-items: center; justify-content: center;
  gap: 12px; padding: 10px 24px; font-weight: 700; font-size: 1rem;
  letter-spacing: 0.04em;
}
.status-banner.approved  { background: #1a472a; border-bottom: 3px solid #2a9d8f; color: #6ee7b7; }
.status-banner.review    { background: #422010; border-bottom: 3px solid #f4a261; color: #fcd3a8; }
.status-banner.rejected  { background: #3b0a0a; border-bottom: 3px solid #e63946; color: #fca5a5; }

/* ---- Layout ---- */
.app-layout {
  display: flex;
  margin-top: 48px;
  min-height: calc(100vh - 48px);
}

/* ---- Sidebar ---- */
.sidebar {
  width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  position: fixed; left: 0; top: 48px; bottom: 0;
  overflow-y: auto; z-index: 100;
  padding: 20px 0;
}
.sidebar-brand {
  padding: 8px 20px 16px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}
.sidebar-brand h3 {
  font-size: 0.8rem; font-weight: 700; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.12em;
}
.sidebar-brand p {
  font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;
}
.sidebar-nav { list-style: none; }
.sidebar-nav li a {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 20px; color: var(--text-muted);
  text-decoration: none; font-size: 0.82rem; font-weight: 500;
  border-left: 3px solid transparent;
  transition: all 0.15s;
}
.sidebar-nav li a:hover,
.sidebar-nav li a.active {
  background: rgba(240,165,0,0.08);
  color: var(--accent);
  border-left-color: var(--accent);
}
.sidebar-nav li a .nav-icon { font-size: 1rem; width: 20px; text-align: center; }

/* ---- Main Content ---- */
.main-content {
  margin-left: var(--sidebar-w);
  flex: 1; padding: 32px 40px;
  max-width: calc(100% - var(--sidebar-w));
}

/* ---- Report Header ---- */
.report-header {
  display: flex; align-items: center; justify-content: space-between;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 24px 28px; margin-bottom: 28px;
  gap: 20px;
}
.header-left { display: flex; align-items: center; gap: 18px; }
.hemspect-logo-main {
  font-size: 2.8rem; font-weight: 900; letter-spacing: -0.02em;
  background: linear-gradient(135deg, #00ff88, #00d4ff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; text-shadow: none;
}
.hemspect-logo-main span {
  font-size: 0.65em; vertical-align: super; opacity: 0.7;
  -webkit-text-fill-color: #00ff88;
}
.report-title { 
  font-size: 0.85rem; font-weight: 600; color: #5a8ab5; 
  letter-spacing: 0.08em; text-transform: uppercase; margin-top: 4px;
}
.header-right { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; }
.meta-pill {
  display: flex; gap: 8px; align-items: center;
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 20px; padding: 4px 12px; font-size: 0.78rem;
}
.meta-label { color: var(--text-muted); }
.meta-value { color: var(--accent); font-weight: 600; }

/* ---- Section Titles ---- */
.report-section { margin-bottom: 40px; }
.section-title {
  font-size: 1.15rem; font-weight: 700; color: var(--accent);
  display: flex; align-items: center; gap: 10px;
  padding-bottom: 10px; border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
}
.section-icon { font-size: 1.2rem; }

/* ---- Summary Cards ---- */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 16px; margin-bottom: 24px;
}
.summary-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px 20px;
  text-align: center; transition: transform 0.15s;
}
.summary-card:hover { transform: translateY(-2px); }
.summary-card.card-critical { border-top: 3px solid var(--danger); }
.summary-card.card-high     { border-top: 3px solid var(--warning); }
.summary-card.card-medium   { border-top: 3px solid #e9c46a; }
.summary-card.card-low      { border-top: 3px solid var(--success); }
.summary-card.card-score    { border-top: 3px solid var(--info); }
.summary-card.card-total    { border-top: 3px solid var(--accent); }
.card-number {
  font-size: 2.4rem; font-weight: 800;
  font-variant-numeric: tabular-nums; line-height: 1;
}
.card-number.num-critical { color: var(--danger); }
.card-number.num-high     { color: var(--warning); }
.card-number.num-medium   { color: #e9c46a; }
.card-number.num-low      { color: var(--success); }
.card-number.num-total    { color: var(--accent); }
.card-number.num-score    { color: var(--info); }
.card-label {
  font-size: 0.72rem; font-weight: 600;
  color: var(--text-muted); text-transform: uppercase;
  letter-spacing: 0.08em; margin-top: 6px;
}

/* ---- Risk Gauge ---- */
.risk-gauge-container {
  display: flex; align-items: center; gap: 40px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 28px 36px;
}
.gauge-svg { flex-shrink: 0; }
.gauge-details { flex: 1; }
.gauge-details h3 { font-size: 1rem; color: var(--text-muted); margin-bottom: 16px; }
.risk-bar-row {
  display: flex; align-items: center; gap: 12px; margin-bottom: 10px;
}
.risk-bar-label { width: 70px; font-size: 0.78rem; font-weight: 600; color: var(--text-muted); }
.risk-bar-track {
  flex: 1; height: 8px; background: var(--surface2);
  border-radius: 4px; overflow: hidden;
}
.risk-bar-fill { height: 100%; border-radius: 4px; transition: width 1.2s ease; }
.risk-bar-fill.fill-critical { background: var(--danger); }
.risk-bar-fill.fill-high     { background: var(--warning); }
.risk-bar-fill.fill-medium   { background: #e9c46a; }
.risk-bar-fill.fill-low      { background: var(--success); }
.risk-bar-count { font-size: 0.82rem; font-weight: 700; min-width: 30px; text-align: right; }

/* ---- Compliance Matrix ---- */
.compliance-framework { margin-bottom: 28px; }
.compliance-framework h4 {
  font-size: 0.82rem; font-weight: 700; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 12px;
}
.control-grid {
  display: flex; flex-wrap: wrap; gap: 10px;
}
.control-chip {
  padding: 8px 14px; border-radius: 8px;
  font-size: 0.8rem; font-weight: 600; display: flex;
  flex-direction: column; align-items: center; gap: 4px;
  min-width: 90px; text-align: center;
}
.control-chip.ctrl-pass {
  background: rgba(42,157,143,0.15); border: 1px solid var(--success); color: var(--success);
}
.control-chip.ctrl-fail {
  background: rgba(230,57,70,0.15); border: 1px solid var(--danger); color: var(--danger);
}
.control-chip.ctrl-gray {
  background: rgba(139,160,190,0.1); border: 1px solid var(--border); color: var(--text-muted);
}
.ctrl-icon { font-size: 1rem; }
.ctrl-id   { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; }

/* ---- Findings Table ---- */
.filter-bar {
  display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;
}
.filter-btn {
  padding: 6px 16px; border-radius: 20px; border: 1px solid var(--border);
  background: var(--surface2); color: var(--text-muted); cursor: pointer;
  font-size: 0.78rem; font-weight: 600; font-family: inherit;
  transition: all 0.15s;
}
.filter-btn:hover, .filter-btn.active {
  background: var(--accent); color: #000; border-color: var(--accent);
}
.filter-btn.btn-critical.active { background: var(--danger); color: #fff; border-color: var(--danger); }
.filter-btn.btn-high.active     { background: var(--warning); color: #000; border-color: var(--warning); }
.filter-btn.btn-medium.active   { background: #e9c46a; color: #000; border-color: #e9c46a; }
.filter-btn.btn-low.active      { background: var(--success); color: #fff; border-color: var(--success); }
.filter-count { margin-left: auto; font-size: 0.78rem; color: var(--text-muted); }

.findings-table-wrap {
  overflow-x: auto; border-radius: 10px;
  border: 1px solid var(--border);
}
table.findings-table {
  width: 100%; border-collapse: collapse; font-size: 0.82rem;
}
.findings-table th {
  background: var(--surface); color: var(--accent);
  padding: 11px 14px; text-align: left; font-weight: 700;
  font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.06em;
  white-space: nowrap; cursor: pointer; user-select: none;
  border-bottom: 1px solid var(--border);
}
.findings-table th:hover { color: var(--accent2); }
.findings-table th .sort-icon { margin-left: 4px; opacity: 0.5; }
.findings-table td {
  padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.04);
  vertical-align: top;
}
.findings-table tr.finding-row { cursor: pointer; transition: background 0.1s; }
.findings-table tr.finding-row:hover { background: rgba(240,165,0,0.05); }
.findings-table tr.finding-row.row-critical td:first-child { border-left: 3px solid var(--danger); }
.findings-table tr.finding-row.row-high td:first-child     { border-left: 3px solid var(--warning); }
.findings-table tr.finding-row.row-medium td:first-child   { border-left: 3px solid #e9c46a; }
.findings-table tr.finding-row.row-low td:first-child      { border-left: 3px solid var(--success); }
.findings-table tr.finding-row.hidden { display: none; }

.sev-badge {
  display: inline-block; padding: 3px 9px; border-radius: 12px;
  font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em;
}
.sev-CRITICAL { background: rgba(230,57,70,0.2); color: #ff6b7a; border: 1px solid var(--danger); }
.sev-HIGH     { background: rgba(244,162,97,0.2); color: #ffb87a; border: 1px solid var(--warning); }
.sev-MEDIUM   { background: rgba(233,196,106,0.2); color: #f5d77e; border: 1px solid #e9c46a; }
.sev-LOW      { background: rgba(42,157,143,0.2); color: #5dddd5; border: 1px solid var(--success); }

.detail-row td {
  background: var(--surface2); padding: 0;
}
.detail-row.hidden { display: none; }
.detail-content {
  padding: 16px 20px; border-top: 1px solid var(--border);
  font-size: 0.8rem;
}
.detail-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 12px;
}
.detail-field label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 4px; }
.detail-field p { color: var(--text); font-size: 0.82rem; }
.detail-code {
  background: #0a0f1a; border: 1px solid var(--border); border-radius: 6px;
  padding: 10px 14px; font-family: 'Courier New', monospace;
  font-size: 0.78rem; color: #90cdf4; word-break: break-all;
}
.compliance-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.compliance-tag {
  padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 600;
  background: rgba(72,149,239,0.15); color: #90c2f8; border: 1px solid rgba(72,149,239,0.3);
}
.expand-icon { float: right; transition: transform 0.2s; display: inline-block; }
.expanded .expand-icon { transform: rotate(180deg); }

/* ---- MITRE Heatmap ---- */
.mitre-scroll { overflow-x: auto; }
table.mitre-table {
  border-collapse: collapse; font-size: 0.75rem; min-width: max-content;
}
.mitre-table th {
  background: var(--surface); color: var(--accent);
  padding: 8px 12px; font-size: 0.68rem; text-transform: uppercase;
  letter-spacing: 0.06em; border: 1px solid var(--border); white-space: nowrap;
}
.mitre-table td {
  padding: 7px 12px; border: 1px solid var(--border);
  text-align: center; min-width: 90px;
}
.heat-0 { background: var(--surface2); color: var(--text-muted); }
.heat-1 { background: rgba(244,162,97,0.25); color: #ffb87a; font-weight: 700; }
.heat-2 { background: rgba(230,57,70,0.35); color: #ff6b7a;  font-weight: 700; }
.technique-id { font-family: 'Courier New', monospace; font-size: 0.7rem; }

/* ---- SBOM Section ---- */
.sbom-placeholder { color: var(--text-muted); font-style: italic; padding: 20px; }

/* ---- Workflow Timeline ---- */
.workflow-stage-grid {
  display: flex; gap: 0; margin-bottom: 28px; overflow-x: auto;
}
.workflow-stage {
  flex: 1; min-width: 120px; padding: 14px 16px; text-align: center;
  background: var(--surface2); border: 1px solid var(--border);
  font-size: 0.75rem; position: relative;
}
.workflow-stage:not(:last-child)::after {
  content: '▶'; position: absolute; right: -10px; top: 50%;
  transform: translateY(-50%); color: var(--border); z-index: 1;
}
.workflow-stage.ws-current {
  background: rgba(240,165,0,0.12); border-color: var(--accent); color: var(--accent);
}
.workflow-stage.ws-done {
  background: rgba(42,157,143,0.12); border-color: var(--success); color: var(--success);
}
.workflow-stage.ws-rejected {
  background: rgba(230,57,70,0.12); border-color: var(--danger); color: var(--danger);
}
.ws-icon { font-size: 1.2rem; display: block; margin-bottom: 4px; }
.ws-label { font-weight: 700; font-size: 0.72rem; }

/* ---- Audit Trail ---- */
.audit-timeline { position: relative; padding-left: 28px; }
.audit-timeline::before {
  content: ''; position: absolute; left: 8px; top: 0; bottom: 0;
  width: 2px; background: var(--border);
}
.audit-entry {
  position: relative; margin-bottom: 20px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px;
}
.audit-entry::before {
  content: ''; position: absolute; left: -24px; top: 18px;
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--accent); border: 2px solid var(--primary);
}
.audit-meta { display: flex; gap: 12px; align-items: center; margin-bottom: 6px; flex-wrap: wrap; }
.audit-time { font-size: 0.72rem; color: var(--text-muted); font-family: monospace; }
.sidebar-brand h3 { font-size: 1.3rem; margin-bottom: 5px; color: var(--accent); }
.sidebar-brand p { font-size: 0.75rem; color: var(--text-muted); word-break: break-all; }
.hemspect-logo-sidebar {
  font-size: 1.5rem; font-weight: 900; letter-spacing: -0.02em;
  background: linear-gradient(135deg, #00ff88, #00d4ff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; text-shadow: none;
  margin-bottom: 5px;
}
.hemspect-logo-sidebar span {
  font-size: 0.65em; vertical-align: super; opacity: 0.7;
  -webkit-text-fill-color: #00ff88;
}
.audit-actor { font-size: 0.78rem; font-weight: 700; color: var(--accent); }
.audit-event { font-size: 0.72rem; color: var(--info);
  background: rgba(72,149,239,0.12); padding: 2px 8px; border-radius: 4px; }
.audit-detail { font-size: 0.78rem; color: var(--text-muted); }

/* ---- Remediation Tracker ---- */
.remediation-group { margin-bottom: 24px; }
.remediation-group h4 {
  font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.08em; margin-bottom: 12px; padding: 6px 12px;
  border-radius: 6px;
}
.remediation-group.rem-critical h4 { background: rgba(230,57,70,0.15); color: var(--danger); }
.remediation-group.rem-high     h4 { background: rgba(244,162,97,0.15); color: var(--warning); }
.remediation-group.rem-medium   h4 { background: rgba(233,196,106,0.15); color: #e9c46a; }
.remediation-group.rem-low      h4 { background: rgba(42,157,143,0.15); color: var(--success); }

.rem-item {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.04);
  font-size: 0.82rem;
}
.rem-checkbox {
  width: 16px; height: 16px; border: 2px solid var(--border);
  border-radius: 3px; flex-shrink: 0; margin-top: 2px; print-color-adjust: exact;
}
.rem-file { color: var(--text-muted); font-size: 0.72rem; }
.rem-text { color: var(--text); }
.rem-mitre { font-family: monospace; font-size: 0.7rem;
  color: var(--info); background: rgba(72,149,239,0.1);
  padding: 1px 6px; border-radius: 3px; margin-top: 4px; display: inline-block; }

/* ---- Footer ---- */
.report-footer {
  margin-top: 40px; padding: 20px; background: var(--surface);
  border: 1px solid var(--border); border-radius: 10px;
  font-size: 0.75rem; color: var(--text-muted);
}
.footer-row {
  display: flex; gap: 24px; align-items: center; flex-wrap: wrap; margin-bottom: 8px;
}
.footer-compliance { color: var(--accent); font-weight: 600; font-size: 0.72rem; }
.report-footer code { color: #6dffb9; font-family: monospace; }

/* ---- Password Intelligence Section ---- */
.pwd-section-header {
  background: linear-gradient(135deg, #0a1628 0%, #1a0a2e 40%, #0d1f3c 100%);
  border: 1px solid rgba(240,165,0,0.2); border-radius: 16px;
  padding: 28px 32px; margin-bottom: 28px; position: relative; overflow: hidden;
}
.pwd-section-header::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, #e63946, #f4a261, #e9c46a, #2a9d8f, #e63946);
  background-size: 300% auto;
  animation: pwd-gradient-sweep 4s ease-in-out infinite;
}
@keyframes pwd-gradient-sweep {
  0% { background-position: 0% center; }
  50% { background-position: 300% center; }
  100% { background-position: 0% center; }
}
.pwd-section-header .pwd-brand {
  display: flex; align-items: center; gap: 12px; margin-bottom: 6px;
}
.pwd-section-header .pwd-brand-icon {
  font-size: 2rem; filter: drop-shadow(0 0 8px rgba(240,165,0,0.4));
}
.pwd-section-header .pwd-brand-title {
  font-size: 1.3rem; font-weight: 800; color: var(--accent);
  letter-spacing: 0.02em;
}
.pwd-section-header .pwd-brand-sub {
  font-size: 0.75rem; color: var(--text-muted); letter-spacing: 0.06em;
}

/* Password Summary Cards */
.pwd-cards-grid {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 16px; margin-bottom: 28px;
}
.pwd-card {
  background: linear-gradient(145deg, var(--surface) 0%, var(--surface2) 100%);
  border: 1px solid var(--border); border-radius: 12px;
  padding: 20px 22px; text-align: center;
  position: relative; overflow: hidden;
  backdrop-filter: blur(10px);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.pwd-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3);
}
.pwd-card::after {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
}
.pwd-card.pwd-card-total::after { background: linear-gradient(90deg, var(--accent), #ffc233); }
.pwd-card.pwd-card-plaintext::after { background: linear-gradient(90deg, #e63946, #ff6b7a); }
.pwd-card.pwd-card-files::after { background: linear-gradient(90deg, #4895ef, #64b5f6); }
.pwd-card.pwd-card-types::after { background: linear-gradient(90deg, #8b5cf6, #a78bfa); }
.pwd-card-number {
  font-size: 2.6rem; font-weight: 900; line-height: 1;
  font-variant-numeric: tabular-nums;
  margin-bottom: 6px;
}
.pwd-card.pwd-card-total .pwd-card-number { color: var(--accent); }
.pwd-card.pwd-card-plaintext .pwd-card-number { color: #e63946; }
.pwd-card.pwd-card-files .pwd-card-number { color: #4895ef; }
.pwd-card.pwd-card-types .pwd-card-number { color: #8b5cf6; }
.pwd-card-label {
  font-size: 0.7rem; font-weight: 700; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.08em;
}

/* Password Charts Row */
.pwd-charts-row {
  display: grid; grid-template-columns: 340px 1fr;
  gap: 24px; margin-bottom: 28px;
}
.pwd-chart {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 24px;
}
.pwd-chart-title {
  font-size: 0.82rem; font-weight: 700; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.08em;
  margin-bottom: 16px;
}
.pwd-chart svg { display: block; margin: 0 auto; }
.pwd-doughnut-legend {
  display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px;
  justify-content: center;
}
.pwd-legend-item {
  display: flex; align-items: center; gap: 6px;
  font-size: 0.72rem; color: var(--text-muted);
}
.pwd-legend-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
}
.pwd-bar-container { display: flex; flex-direction: column; gap: 10px; }
.pwd-bar-row {
  display: flex; align-items: center; gap: 12px;
}
.pwd-bar-label {
  width: 160px; font-size: 0.75rem; color: var(--text-muted);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  font-family: 'Courier New', monospace;
}
.pwd-bar-track {
  flex: 1; height: 22px; background: var(--surface2);
  border-radius: 4px; overflow: hidden; position: relative;
}
.pwd-bar-fill {
  height: 100%; border-radius: 4px;
  background: linear-gradient(90deg, var(--accent), #ffc233);
  transition: width 1s ease 0.3s;
  min-width: 2px;
}
.pwd-bar-count {
  min-width: 28px; font-size: 0.78rem; font-weight: 700;
  color: var(--accent); text-align: right;
}

/* Password Findings Table */
.pwd-filter-bar {
  display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center;
}
.pwd-filter-btn {
  padding: 6px 16px; border-radius: 20px; border: 1px solid var(--border);
  background: var(--surface2); color: var(--text-muted); cursor: pointer;
  font-size: 0.78rem; font-weight: 600; font-family: inherit;
  transition: all 0.15s;
}
.pwd-filter-btn:hover { background: rgba(240,165,0,0.15); color: var(--text); border-color: var(--accent); }
.pwd-filter-btn.active { background: var(--accent); color: #000; border-color: var(--accent); }
.pwd-filter-btn.pwd-btn-critical.active { background: #e63946; color: #fff; border-color: #e63946; }
.pwd-filter-btn.pwd-btn-high.active { background: #f4a261; color: #000; border-color: #f4a261; }
.pwd-filter-btn.pwd-btn-medium.active { background: #e9c46a; color: #000; border-color: #e9c46a; }
.pwd-filter-btn.pwd-btn-low.active { background: #2a9d8f; color: #fff; border-color: #2a9d8f; }
.pwd-filter-sep {
  width: 1px; height: 24px; background: var(--border); margin: 0 4px;
}
.pwd-type-select {
  padding: 6px 12px; border-radius: 20px; border: 1px solid var(--border);
  background: var(--surface2); color: var(--text-muted); cursor: pointer;
  font-size: 0.78rem; font-weight: 500; font-family: inherit;
  appearance: none; -webkit-appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238ba0be'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 10px center;
  padding-right: 28px;
}
.pwd-filter-count {
  margin-left: auto; font-size: 0.78rem; color: var(--text-muted);
}

.pwd-table-wrap {
  overflow-x: auto; border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--surface);
}
table.pwd-table {
  width: 100%; border-collapse: collapse; font-size: 0.82rem;
}
.pwd-table th {
  background: rgba(240,165,0,0.06); color: var(--accent);
  padding: 12px 14px; text-align: left; font-weight: 700;
  font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.06em;
  white-space: nowrap; cursor: pointer; user-select: none;
  border-bottom: 2px solid var(--border);
}
.pwd-table th:hover { color: var(--accent2); }
.pwd-table th .sort-icon { margin-left: 4px; opacity: 0.4; font-size: 0.7rem; }
.pwd-table td {
  padding: 11px 14px; border-bottom: 1px solid rgba(255,255,255,0.04);
  vertical-align: middle;
}
.pwd-table tr.pwd-row { cursor: pointer; transition: background 0.12s; }
.pwd-table tr.pwd-row:hover { background: rgba(240,165,0,0.05); }
.pwd-table tr.pwd-row td:first-child {
  border-left: 3px solid transparent; padding-left: 11px;
}
.pwd-table tr.pwd-row.pwd-sev-critical td:first-child { border-left-color: #e63946; }
.pwd-table tr.pwd-row.pwd-sev-high td:first-child { border-left-color: #f4a261; }
.pwd-table tr.pwd-row.pwd-sev-medium td:first-child { border-left-color: #e9c46a; }
.pwd-table tr.pwd-row.pwd-sev-low td:first-child { border-left-color: #2a9d8f; }
.pwd-table tr.pwd-row.hidden { display: none; }

.pwd-severity {
  display: inline-block; padding: 3px 10px; border-radius: 12px;
  font-size: 0.7rem; font-weight: 800; letter-spacing: 0.05em;
  text-transform: uppercase;
}
.pwd-severity-critical { background: rgba(230,57,70,0.2); color: #ff6b7a; border: 1px solid rgba(230,57,70,0.4); }
.pwd-severity-high { background: rgba(244,162,97,0.2); color: #ffb87a; border: 1px solid rgba(244,162,97,0.4); }
.pwd-severity-medium { background: rgba(233,196,106,0.2); color: #f5d77e; border: 1px solid rgba(233,196,106,0.4); }
.pwd-severity-low { background: rgba(42,157,143,0.2); color: #5dddd5; border: 1px solid rgba(42,157,143,0.4); }

/* Password Masking */
.pwd-mask-wrap {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: 'Courier New', monospace; font-size: 0.78rem;
}
.pwd-mask-value {
  color: #ff6b7a; background: rgba(230,57,70,0.08);
  padding: 2px 8px; border-radius: 4px;
  letter-spacing: 0.1em; max-width: 200px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.pwd-mask-value.pwd-masked {
  color: var(--text-muted); letter-spacing: 0.2em;
}
.pwd-reveal {
  background: none; border: 1px solid var(--border);
  border-radius: 6px; padding: 2px 6px; cursor: pointer;
  font-size: 0.82rem; color: var(--text-muted);
  transition: all 0.15s; line-height: 1;
}
.pwd-reveal:hover {
  background: rgba(240,165,0,0.1); border-color: var(--accent);
  color: var(--accent);
}

/* Context Highlighting */
.pwd-highlight {
  background: rgba(240,165,0,0.25); color: #ffc233;
  padding: 1px 3px; border-radius: 3px;
  font-weight: 700; border: 1px solid rgba(240,165,0,0.3);
}
.pwd-context-code {
  background: #060b14; border: 1px solid var(--border); border-radius: 6px;
  padding: 8px 12px; font-family: 'Courier New', monospace;
  font-size: 0.75rem; color: #90cdf4; word-break: break-all;
  white-space: pre-wrap; max-height: 120px; overflow-y: auto;
}

/* Confidence Bar */
.pwd-conf-bar {
  display: flex; align-items: center; gap: 6px;
}
.pwd-conf-track {
  width: 60px; height: 6px; background: var(--surface2);
  border-radius: 3px; overflow: hidden;
}
.pwd-conf-fill {
  height: 100%; border-radius: 3px;
  transition: width 0.6s ease;
}
.pwd-conf-fill.conf-high { background: #e63946; }
.pwd-conf-fill.conf-med { background: #f4a261; }
.pwd-conf-fill.conf-low { background: #2a9d8f; }
.pwd-conf-text {
  font-size: 0.7rem; color: var(--text-muted); min-width: 30px;
}

/* Copy Button */
.pwd-copy-btn {
  background: none; border: 1px solid var(--border);
  border-radius: 6px; padding: 3px 8px; cursor: pointer;
  font-size: 0.7rem; color: var(--text-muted);
  transition: all 0.15s; font-family: inherit;
}
.pwd-copy-btn:hover {
  background: rgba(240,165,0,0.1); border-color: var(--accent);
  color: var(--accent);
}
.pwd-copy-btn.copied {
  background: rgba(42,157,143,0.15); border-color: var(--success);
  color: var(--success);
}

/* Detail Row */
.pwd-detail-row td {
  background: rgba(22,32,50,0.95); padding: 0;
}
.pwd-detail-row.hidden { display: none; }
.pwd-detail-content {
  padding: 18px 22px; border-top: 1px solid var(--border);
}
.pwd-detail-grid {
  display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-bottom: 14px;
}
.pwd-detail-field label {
  font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;
  letter-spacing: 0.08em; display: block; margin-bottom: 4px;
}
.pwd-detail-field p { color: var(--text); font-size: 0.8rem; }
.pwd-detail-tags {
  display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;
}
.pwd-detail-tag {
  padding: 2px 8px; border-radius: 4px; font-size: 0.66rem; font-weight: 600;
}
.pwd-detail-tag.tag-mitre {
  background: rgba(72,149,239,0.15); color: #90c2f8;
  border: 1px solid rgba(72,149,239,0.3);
}
.pwd-detail-tag.tag-cwe {
  background: rgba(244,162,97,0.15); color: #ffb87a;
  border: 1px solid rgba(244,162,97,0.3);
}
.pwd-detail-tag.tag-compliance {
  background: rgba(139,92,246,0.15); color: #a78bfa;
  border: 1px solid rgba(139,92,246,0.3);
}

/* False Positive Exclusions */
.pwd-excluded {
  margin-top: 28px; border: 1px solid rgba(139,160,190,0.15);
  border-radius: 12px; overflow: hidden;
}
.pwd-excluded-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 20px; background: rgba(139,160,190,0.05);
  cursor: pointer; user-select: none;
  border-bottom: 1px solid rgba(139,160,190,0.1);
}
.pwd-excluded-header:hover { background: rgba(139,160,190,0.08); }
.pwd-excluded-title {
  font-size: 0.82rem; font-weight: 700; color: var(--text-muted);
  display: flex; align-items: center; gap: 8px;
}
.pwd-excluded-toggle {
  font-size: 0.9rem; color: var(--text-muted);
  transition: transform 0.2s;
}
.pwd-excluded.expanded .pwd-excluded-toggle { transform: rotate(180deg); }
.pwd-excluded-body {
  max-height: 0; overflow: hidden; transition: max-height 0.3s ease;
}
.pwd-excluded.expanded .pwd-excluded-body {
  max-height: 2000px;
}
.pwd-excluded-item {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 20px; border-bottom: 1px solid rgba(139,160,190,0.06);
  font-size: 0.78rem; color: var(--text-muted); opacity: 0.7;
}
.pwd-excluded-item:last-child { border-bottom: none; }
.pwd-excluded-reason {
  font-size: 0.68rem; padding: 2px 8px; border-radius: 4px;
  background: rgba(139,160,190,0.1); color: var(--text-muted);
}
.pwd-excluded-file {
  font-family: 'Courier New', monospace; font-size: 0.72rem;
  color: var(--text-muted);
}

/* ---- Print styles ---- */
@media print {
  :root { --primary: #fff; --surface: #f5f7fa; --text: #111; --accent: #0a1628; --border: #ccc; }
  .status-banner { position: static; color-adjust: exact; print-color-adjust: exact; }
  .sidebar { display: none; }
  .main-content { margin-left: 0; padding: 20px; }
  .app-layout { display: block; }
  .report-section { page-break-inside: avoid; }
  .summary-card, .control-chip { border: 1px solid #ccc !important; }
  .filter-bar, .filter-btn, .pwd-filter-bar, .pwd-filter-btn { display: none; }
  .findings-table tr.hidden { display: table-row !important; }
  .detail-row.hidden, .pwd-detail-row.hidden { display: table-row !important; }
  .gauge-svg { display: none; }
  .pwd-mask-value.pwd-masked { color: #333; }
  .pwd-reveal { display: none; }
  body { font-size: 11px; }
  * { animation: none !important; transition: none !important; }
}
</style>"""

    # ------------------------------------------------------------------ #
    #  Status Banner                                                       #
    # ------------------------------------------------------------------ #

    def _status_banner(self, approval: str) -> str:
        classes = {
            "APPROVED":        ("approved",  "✔", "APPROVED FOR DEPLOYMENT"),
            "REVIEW_REQUIRED": ("review",    "⚠", "SECURITY REVIEW REQUIRED"),
            "REJECTED":        ("rejected",  "✖", "DEPLOYMENT REJECTED"),
        }
        cls, icon, label = classes.get(approval, ("review", "⚠", approval))
        return f'<div class="status-banner {cls}">{icon}&nbsp;{label}</div>'

    # ------------------------------------------------------------------ #
    #  Sidebar                                                             #
    # ------------------------------------------------------------------ #

    def _sidebar(self) -> str:
        nav_items = [
            ("sec-executive",  "📊", "Executive Summary"),
            ("sec-pwdintel",   "🔑", "Password Intelligence"),
            ("sec-risk",       "🎯", "Risk Assessment"),
            ("sec-compliance", "📋", "Compliance Matrix"),
            ("sec-hemspect",   "⚡", "HemSpect™ Engine"),
            ("sec-findings",   "🔍", "Other Findings"),
            ("sec-mitre",      "🗺", "MITRE ATT&CK"),
            ("sec-sbom",       "📦", "SBOM Inventory"),
            ("sec-workflow",   "✅", "Approval Workflow"),
            ("sec-audit",      "🕵", "Audit Trail"),
            ("sec-remediation","🔧", "Remediation"),
        ]
        items_html = "\n".join(
            f'<li><a href="#{sec_id}" class="nav-link" data-section="{sec_id}">'
            f'<span class="nav-icon">{icon}</span>{label}</a></li>'
            for sec_id, icon, label in nav_items
        )
        pkg = self.findings.get("package", "Package")
        return f"""
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="hemspect-logo-sidebar">⚡ HemSpect<span>™</span></div>
    <p>v{SCANNER_VERSION} — {pkg}</p>
  </div>
  <ul class="sidebar-nav">
{items_html}
  </ul>
</aside>"""

    # ------------------------------------------------------------------ #
    #  Section: HemSpect™ Data Leakage Intelligence Engine                   #
    # ------------------------------------------------------------------ #

    def _section_hemspect(self) -> str:
        """Build the HemSpect branded data leakage intelligence section."""
        issues = self._issues
        # Filter HemSpect findings
        hs_findings = [i for i in issues if i.get("type") == "DataLeakage" or str(i.get("rule_id", "")).startswith("hemspect_")]
        tier1 = [f for f in hs_findings if f.get("subtype") == "DangerousFileType"]
        tier2 = [f for f in hs_findings if f.get("subtype") == "SuspiciousFilename"]
        tier3 = [f for f in hs_findings if f.get("subtype") == "ContentMatch"]
        total = len(hs_findings)

        # Status determination
        if total == 0:
            status_html = '<span class="hemspect-status hemspect-clean">✔ CLEAN — No data leakage detected</span>'
        else:
            crit = sum(1 for f in hs_findings if f.get("severity") == "CRITICAL")
            high = sum(1 for f in hs_findings if f.get("severity") == "HIGH")
            status_html = f'<span class="hemspect-status hemspect-alert">⚠ {total} DATA LEAKAGE ISSUE(S) — {crit} Critical, {high} High</span>'

        # Build findings rows
        rows = ""
        for f in hs_findings:
            sev = f.get("severity", "MEDIUM")
            sev_cls = f"sev-{sev.lower()}"
            file_name = Path(f.get("file", "")).name
            rows += f"""<tr>
              <td><span class="sev-badge {sev_cls}">{sev}</span></td>
              <td>{f.get("subtype", "Unknown")}</td>
              <td class="mono">{file_name}</td>
              <td>{f.get("match", "")[:80]}</td>
              <td>{f.get("description", "")}</td>
            </tr>"""

        findings_table = ""
        if rows:
            findings_table = f"""
<table class="hemspect-table">
  <thead><tr><th>Severity</th><th>Tier</th><th>File</th><th>Match</th><th>Description</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

        return f"""
<style>
  .hemspect-card {{
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 50%, #0a1628 100%);
    border: 1px solid #1a3a5c; border-radius: 14px; padding: 28px 32px;
    margin-bottom: 24px; position: relative; overflow: hidden;
  }}
  .hemspect-card::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, #00ff88, #00d4ff, #8b5cf6, #00ff88);
    background-size: 200% auto;
    animation: hemspect-glow 3s ease-in-out infinite;
  }}
  @keyframes hemspect-glow {{
    0% {{ background-position: 0% center; }}
    50% {{ background-position: 200% center; }}
    100% {{ background-position: 0% center; }}
  }}
  .hemspect-brand {{
    display: flex; align-items: center; gap: 14px; margin-bottom: 18px;
  }}
  .hemspect-logo {{
    font-size: 2rem; font-weight: 900; letter-spacing: -0.02em;
    background: linear-gradient(135deg, #00ff88, #00d4ff);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text; text-shadow: none;
  }}
  .hemspect-logo span {{
    font-size: 0.65em; vertical-align: super; opacity: 0.7;
    -webkit-text-fill-color: #00ff88;
  }}
  .hemspect-tagline {{
    font-size: 0.78rem; color: #5a8ab5; font-weight: 500;
    letter-spacing: 0.08em; text-transform: uppercase;
  }}
  .hemspect-tiers {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px;
    margin: 20px 0;
  }}
  .hemspect-tier {{
    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 16px 18px; text-align: center;
  }}
  .hemspect-tier-num {{
    font-size: 1.8rem; font-weight: 800; line-height: 1;
  }}
  .hemspect-tier.ht-ext .hemspect-tier-num {{ color: #ff6b6b; }}
  .hemspect-tier.ht-name .hemspect-tier-num {{ color: #ffd93d; }}
  .hemspect-tier.ht-deep .hemspect-tier-num {{ color: #6bcb77; }}
  .hemspect-tier-label {{
    font-size: 0.7rem; font-weight: 600; color: #7a9fc2;
    text-transform: uppercase; letter-spacing: 0.06em; margin-top: 6px;
  }}
  .hemspect-status {{
    display: inline-block; padding: 6px 16px; border-radius: 20px;
    font-weight: 700; font-size: 0.82rem; letter-spacing: 0.04em;
  }}
  .hemspect-clean {{
    background: rgba(42,157,143,0.15); color: #5dddd5;
    border: 1px solid rgba(42,157,143,0.3);
  }}
  .hemspect-alert {{
    background: rgba(230,57,70,0.15); color: #ff6b7a;
    border: 1px solid rgba(230,57,70,0.3);
  }}
  .hemspect-table {{
    width: 100%; border-collapse: collapse; font-size: 0.8rem;
    margin-top: 18px;
  }}
  .hemspect-table th {{
    background: rgba(0,212,255,0.08); color: #00d4ff; padding: 10px 12px;
    text-align: left; font-weight: 700; font-size: 0.72rem;
    text-transform: uppercase; letter-spacing: 0.06em;
    border-bottom: 1px solid rgba(0,212,255,0.15);
  }}
  .hemspect-table td {{
    padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.04);
    color: #c0d0e0;
  }}
  .hemspect-table tr:hover {{ background: rgba(0,255,136,0.04); }}
  .hemspect-table .mono {{ font-family: 'Fira Code', monospace; font-size: 0.78rem; color: #f0a500; }}
</style>

<div class="hemspect-card">
  <div class="hemspect-brand">
    <div class="hemspect-logo">⚡ HemSpect<span>™</span></div>
    <div class="hemspect-tagline">Data Leakage Intelligence Engine</div>
  </div>

  <div class="hemspect-tiers">
    <div class="hemspect-tier ht-ext">
      <div class="hemspect-tier-num">{len(tier1)}</div>
      <div class="hemspect-tier-label">Tier 1 — Extensions</div>
    </div>
    <div class="hemspect-tier ht-name">
      <div class="hemspect-tier-num">{len(tier2)}</div>
      <div class="hemspect-tier-label">Tier 2 — Filenames</div>
    </div>
    <div class="hemspect-tier ht-deep">
      <div class="hemspect-tier-num">{len(tier3)}</div>
      <div class="hemspect-tier-label">Tier 3 — Deep Content</div>
    </div>
  </div>

  {status_html}

  {findings_table}
</div>
"""

    # ------------------------------------------------------------------ #
    #  Section: Password Intelligence                                      #
    # ------------------------------------------------------------------ #

    def _get_credential_rule_ids(self) -> set:
        """Return the master set of rule IDs considered credential-related."""
        return {
            'hardcoded_credential', 'credential_dumping', 'credential_in_script',
            'plaintext_password', 'api_key_exposure', 'connection_string_exposure',
            'secure_string_plaintext', 'password_in_config',
            'password_string', 'connection_string_password', 'bearer_token',
            'api_key', 'aws_access_key', 'azure_storage_key', 'registry_password',
            'hemspect_sql_conn_string', 'hemspect_oledb_conn_string',
            'hemspect_mongodb_uri', 'hemspect_jdbc_conn_string',
            'hemspect_xml_password_element', 'hemspect_xml_password_attribute',
            'hemspect_ps_securestring_plaintext', 'hemspect_azure_client_secret',
            'hemspect_azure_sas_token', 'hemspect_bearer_token',
            'hemspect_smtp_credentials', 'hemspect_dsn_string',
            'hemspect_wifi_password', 'hemspect_reg_stored_credential',
            'hemspect_docker_auth', 'hemspect_gcp_service_account',
            'hemspect_dotnet_machine_key', 'hemspect_unattend_password',
        }

    def _get_credential_findings(self):
        """Filter issues to get credential-related findings."""
        cred_rule_ids = self._get_credential_rule_ids()
        results = []
        for i in self._issues:
            if i.get('is_false_positive', False):
                continue
            if i.get('type') == 'Credential':
                results.append(i)
            elif i.get('type') == 'DataLeakage' and i.get('rule_id', '') in cred_rule_ids:
                results.append(i)
            elif i.get('pattern', '') in cred_rule_ids or i.get('subtype', '') in cred_rule_ids:
                results.append(i)
        return results

    def _get_false_positive_credentials(self):
        """Get credential findings marked as false positives."""
        cred_rule_ids = self._get_credential_rule_ids()
        results = []
        for i in self._issues:
            if not i.get('is_false_positive', False):
                continue
            if i.get('type') == 'Credential':
                results.append(i)
            elif i.get('type') == 'DataLeakage' and i.get('rule_id', '') in cred_rule_ids:
                results.append(i)
            elif i.get('pattern', '') in cred_rule_ids or i.get('subtype', '') in cred_rule_ids:
                results.append(i)
        return results

    def _section_password_intelligence(self) -> str:
        """Build the Password Intelligence hero section."""
        import html as html_mod
        import math

        cred_findings = self._get_credential_findings()
        fp_findings = self._get_false_positive_credentials()
        cred_findings_sorted = sorted(cred_findings, key=lambda x: SEV_ORDER.get(x.get('severity', 'INFO'), 99))

        total_creds = len(cred_findings)
        plaintext_count = sum(
            1 for f in cred_findings
            if f.get('extracted_value') and f.get('confidence', 0) >= 0.9
        )
        unique_files = len(set(f.get('file', '') for f in cred_findings if f.get('file')))
        subtypes = set()
        for f in cred_findings:
            st = f.get('pattern', f.get('subtype', ''))
            if st:
                subtypes.add(st)
        type_count = len(subtypes)

        # ── Summary Cards ──
        cards_html = f"""
<div class="pwd-cards-grid">
  <div class="pwd-card pwd-card-total">
    <div class="pwd-card-number" data-counter="{total_creds}">{total_creds}</div>
    <div class="pwd-card-label">Credential Findings</div>
  </div>
  <div class="pwd-card pwd-card-plaintext">
    <div class="pwd-card-number" data-counter="{plaintext_count}">{plaintext_count}</div>
    <div class="pwd-card-label">Plaintext Passwords</div>
  </div>
  <div class="pwd-card pwd-card-files">
    <div class="pwd-card-number" data-counter="{unique_files}">{unique_files}</div>
    <div class="pwd-card-label">Files Affected</div>
  </div>
  <div class="pwd-card pwd-card-types">
    <div class="pwd-card-number" data-counter="{type_count}">{type_count}</div>
    <div class="pwd-card-label">Credential Types</div>
  </div>
</div>"""

        # ── Doughnut Chart Data ──
        type_counts = {}
        for f in cred_findings:
            st = f.get('pattern', f.get('subtype', 'unknown'))
            type_counts[st] = type_counts.get(st, 0) + 1

        doughnut_colors = [
            '#e63946', '#f4a261', '#e9c46a', '#2a9d8f', '#4895ef',
            '#8b5cf6', '#6dffb9', '#ff6b7a', '#64b5f6', '#a78bfa',
        ]

        # Build SVG doughnut using arc paths
        doughnut_svg = ""
        doughnut_legend = ""
        if type_counts:
            cx, cy, r_outer, r_inner = 100, 100, 85, 55
            total_count = sum(type_counts.values())
            sorted_types = sorted(type_counts.items(), key=lambda x: -x[1])
            start_angle = -90  # Start from top
            arcs = []
            legend_items = []

            for idx, (tname, tcount) in enumerate(sorted_types):
                color = doughnut_colors[idx % len(doughnut_colors)]
                pct = tcount / total_count if total_count else 0
                sweep = pct * 360
                end_angle = start_angle + sweep

                # Convert to radians
                sa_rad = math.radians(start_angle)
                ea_rad = math.radians(end_angle)

                # Outer arc
                x1o = cx + r_outer * math.cos(sa_rad)
                y1o = cy + r_outer * math.sin(sa_rad)
                x2o = cx + r_outer * math.cos(ea_rad)
                y2o = cy + r_outer * math.sin(ea_rad)

                # Inner arc
                x1i = cx + r_inner * math.cos(ea_rad)
                y1i = cy + r_inner * math.sin(ea_rad)
                x2i = cx + r_inner * math.cos(sa_rad)
                y2i = cy + r_inner * math.sin(sa_rad)

                large_arc = 1 if sweep > 180 else 0

                if len(sorted_types) == 1:
                    # Full circle - use two semicircles
                    mid_rad = math.radians(start_angle + 180)
                    xmo = cx + r_outer * math.cos(mid_rad)
                    ymo = cy + r_outer * math.sin(mid_rad)
                    xmi = cx + r_inner * math.cos(mid_rad)
                    ymi = cy + r_inner * math.sin(mid_rad)
                    path = (
                        f'M {x1o:.2f} {y1o:.2f} '
                        f'A {r_outer} {r_outer} 0 1 1 {xmo:.2f} {ymo:.2f} '
                        f'A {r_outer} {r_outer} 0 1 1 {x1o:.2f} {y1o:.2f} '
                        f'Z '
                        f'M {x2i:.2f} {y2i:.2f} '
                        f'A {r_inner} {r_inner} 0 1 0 {xmi:.2f} {ymi:.2f} '
                        f'A {r_inner} {r_inner} 0 1 0 {x2i:.2f} {y2i:.2f} Z'
                    )
                else:
                    path = (
                        f'M {x1o:.2f} {y1o:.2f} '
                        f'A {r_outer} {r_outer} 0 {large_arc} 1 {x2o:.2f} {y2o:.2f} '
                        f'L {x1i:.2f} {y1i:.2f} '
                        f'A {r_inner} {r_inner} 0 {large_arc} 0 {x2i:.2f} {y2i:.2f} Z'
                    )

                arcs.append(
                    f'<path d="{path}" fill="{color}" stroke="#0a1628" stroke-width="1.5" '
                    f'opacity="0.9" style="transition: opacity 0.2s;" '
                    f'onmouseover="this.style.opacity=1;this.style.filter=\'brightness(1.2)\'" '
                    f'onmouseout="this.style.opacity=0.9;this.style.filter=\'none\'">'
                    f'<title>{html_mod.escape(tname)}: {tcount} ({pct:.0%})</title></path>'
                )
                legend_items.append(
                    f'<span class="pwd-legend-item">'
                    f'<span class="pwd-legend-dot" style="background:{color}"></span>'
                    f'{html_mod.escape(tname)} ({tcount})'
                    f'</span>'
                )
                start_angle = end_angle

            arcs_html = '\n'.join(arcs)
            # Center text
            center_text = (
                f'<text x="{cx}" y="{cy-6}" text-anchor="middle" fill="var(--accent)" '
                f'font-size="20" font-weight="800" font-family="Inter, sans-serif">{total_count}</text>'
                f'<text x="{cx}" y="{cy+12}" text-anchor="middle" fill="#8ba0be" '
                f'font-size="9" font-family="Inter, sans-serif">FINDINGS</text>'
            )
            doughnut_svg = (
                f'<svg width="200" height="200" viewBox="0 0 200 200">'
                f'{arcs_html}{center_text}</svg>'
            )
            doughnut_legend = '<div class="pwd-doughnut-legend">' + ''.join(legend_items) + '</div>'
        else:
            doughnut_svg = (
                '<svg width="200" height="200" viewBox="0 0 200 200">'
                '<circle cx="100" cy="100" r="85" fill="none" stroke="var(--border)" stroke-width="30" opacity="0.3"/>'
                '<text x="100" y="96" text-anchor="middle" fill="var(--text-muted)" '
                'font-size="14" font-family="Inter, sans-serif">No</text>'
                '<text x="100" y="112" text-anchor="middle" fill="var(--text-muted)" '
                'font-size="14" font-family="Inter, sans-serif">Findings</text>'
                '</svg>'
            )

        # ── Bar Chart: Credentials Per File ──
        file_counts = {}
        for f in cred_findings:
            fname = Path(f.get('file', '')).name
            if fname:
                file_counts[fname] = file_counts.get(fname, 0) + 1
        sorted_files = sorted(file_counts.items(), key=lambda x: -x[1])[:10]
        max_file_count = max((c for _, c in sorted_files), default=1)

        bar_rows_html = ""
        for fname, fcount in sorted_files:
            pct = (fcount / max_file_count) * 100 if max_file_count else 0
            bar_rows_html += (
                f'<div class="pwd-bar-row">'
                f'<span class="pwd-bar-label" title="{html_mod.escape(fname)}">{html_mod.escape(fname)}</span>'
                f'<div class="pwd-bar-track">'
                f'<div class="pwd-bar-fill" style="width:0%" data-target-width="{pct:.0f}%"></div>'
                f'</div>'
                f'<span class="pwd-bar-count">{fcount}</span>'
                f'</div>'
            )

        if not bar_rows_html:
            bar_rows_html = '<p style="color:var(--text-muted);font-style:italic;padding:16px 0">No credential findings to chart.</p>'

        charts_html = f"""
<div class="pwd-charts-row">
  <div class="pwd-chart">
    <div class="pwd-chart-title">Credential Type Distribution</div>
    {doughnut_svg}
    {doughnut_legend}
  </div>
  <div class="pwd-chart">
    <div class="pwd-chart-title">Credentials Per File</div>
    <div class="pwd-bar-container">
      {bar_rows_html}
    </div>
  </div>
</div>"""

        # ── Severity counts for filter pills ──
        sev_counts = {}
        for f in cred_findings:
            sv = f.get('severity', 'LOW')
            sev_counts[sv] = sev_counts.get(sv, 0) + 1

        # ── Type filter options ──
        type_options = '<option value="ALL">All Types</option>'
        for st in sorted(subtypes):
            type_options += f'<option value="{html_mod.escape(st)}">{html_mod.escape(st)}</option>'

        filter_html = f"""
<div class="pwd-filter-bar">
  <button class="pwd-filter-btn active" onclick="filterCredentials('ALL', this)">All ({total_creds})</button>
  <button class="pwd-filter-btn pwd-btn-critical" onclick="filterCredentials('CRITICAL', this)">Critical ({sev_counts.get('CRITICAL', 0)})</button>
  <button class="pwd-filter-btn pwd-btn-high" onclick="filterCredentials('HIGH', this)">High ({sev_counts.get('HIGH', 0)})</button>
  <button class="pwd-filter-btn pwd-btn-medium" onclick="filterCredentials('MEDIUM', this)">Medium ({sev_counts.get('MEDIUM', 0)})</button>
  <button class="pwd-filter-btn pwd-btn-low" onclick="filterCredentials('LOW', this)">Low ({sev_counts.get('LOW', 0)})</button>
  <div class="pwd-filter-sep"></div>
  <select class="pwd-type-select" onchange="filterCredentialsByType(this.value)">
    {type_options}
  </select>
  <span class="pwd-filter-count" id="pwd-findings-count">Showing {total_creds} credential findings</span>
</div>"""

        # ── Table Rows ──
        table_rows = []
        for idx, issue in enumerate(cred_findings_sorted):
            sev = issue.get('severity', 'LOW')
            sev_lower = sev.lower()
            file_path = issue.get('file', '')
            file_name = Path(file_path).name
            line_num = issue.get('line', '—')
            pattern = issue.get('pattern', issue.get('subtype', '—'))
            match_text = (issue.get('match') or '').strip()
            extracted = issue.get('extracted_value', '')
            display_pwd = extracted if extracted else match_text
            display_pwd_escaped = html_mod.escape(display_pwd[:60]) if display_pwd else '—'
            ctx = html_mod.escape((issue.get('context') or '')[:400])
            conf = issue.get('confidence', 0)
            conf_pct = f'{conf:.0%}'
            conf_cls = 'conf-high' if conf >= 0.8 else ('conf-med' if conf >= 0.5 else 'conf-low')
            rem = html_mod.escape(issue.get('remediation', 'Review manually'))
            mitre = issue.get('mitre_id', '')
            cwe = issue.get('cwe_id', '')
            desc = html_mod.escape(issue.get('description', ''))

            # Compliance tags
            sub_rule = issue.get('subtype', issue.get('pattern', ''))
            comp_tags = []
            for ctrl, triggers in CONTROL_TRIGGERS.items():
                if sub_rule in triggers or pattern in triggers:
                    comp_tags.append(ctrl)

            # Highlight password in context
            highlighted_ctx = ctx
            if display_pwd and display_pwd != '—':
                safe_pwd = html_mod.escape(display_pwd[:60])
                if safe_pwd in highlighted_ctx:
                    highlighted_ctx = highlighted_ctx.replace(
                        safe_pwd,
                        f'<span class="pwd-highlight">{safe_pwd}</span>'
                    )

            pwd_id = f'pwd-val-{idx}'
            detail_id = f'pwd-detail-{idx}'

            # Detail tags
            detail_tags = ''
            if mitre:
                detail_tags += f'<span class="pwd-detail-tag tag-mitre">{html_mod.escape(mitre)}</span>'
            if cwe:
                detail_tags += f'<span class="pwd-detail-tag tag-cwe">{html_mod.escape(cwe)}</span>'
            for ct in comp_tags[:4]:
                detail_tags += f'<span class="pwd-detail-tag tag-compliance">{html_mod.escape(ct)}</span>'

            table_rows.append(f"""
<tr class="pwd-row pwd-sev-{sev_lower}" onclick="togglePwdDetail('{detail_id}', this)"
    data-severity="{sev}" data-credtype="{html_mod.escape(pattern)}">
  <td><span class="pwd-severity pwd-severity-{sev_lower}">{sev}</span></td>
  <td><strong>{html_mod.escape(file_name)}</strong></td>
  <td style="font-family:monospace;color:var(--text-muted)">{line_num}</td>
  <td style="font-size:0.75rem">{html_mod.escape(pattern)}</td>
  <td>
    <div class="pwd-mask-wrap">
      <span class="pwd-mask-value pwd-masked" id="{pwd_id}" data-real="{display_pwd_escaped}">••••••••</span>
      <button class="pwd-reveal" onclick="event.stopPropagation();togglePasswordMask('{pwd_id}')" title="Toggle visibility">👁</button>
    </div>
  </td>
  <td>
    <div class="pwd-conf-bar">
      <div class="pwd-conf-track">
        <div class="pwd-conf-fill {conf_cls}" style="width:{conf*100:.0f}%"></div>
      </div>
      <span class="pwd-conf-text">{conf_pct}</span>
    </div>
  </td>
  <td>
    <button class="pwd-copy-btn" onclick="event.stopPropagation();copyFilePath(this, '{html_mod.escape(file_path)}')" title="Copy path">📋</button>
  </td>
  <td><span class="expand-icon">▼</span></td>
</tr>
<tr class="pwd-detail-row hidden" id="{detail_id}">
  <td colspan="8">
    <div class="pwd-detail-content">
      <div class="pwd-detail-grid">
        <div class="pwd-detail-field">
          <label>Description</label>
          <p>{desc if desc else '—'}</p>
        </div>
        <div class="pwd-detail-field">
          <label>Remediation</label>
          <p>{rem}</p>
        </div>
        <div class="pwd-detail-field">
          <label>File Path</label>
          <p style="font-family:monospace;font-size:0.72rem;color:var(--info);word-break:break-all">{html_mod.escape(file_path)}</p>
        </div>
      </div>
      <div class="pwd-detail-field" style="margin-bottom:12px">
        <label>Context</label>
        <div class="pwd-context-code">{highlighted_ctx if highlighted_ctx else '—'}</div>
      </div>
      <div class="pwd-detail-field">
        <label>Tags</label>
        <div class="pwd-detail-tags">{detail_tags if detail_tags else '<span style="color:var(--text-muted)">None mapped</span>'}</div>
      </div>
    </div>
  </td>
</tr>""")

        rows_html = '\n'.join(table_rows)

        table_html = f"""
<div class="pwd-table-wrap">
<table class="pwd-table" id="pwd-table">
  <thead>
    <tr>
      <th onclick="sortPwdTable(0)">Severity <span class="sort-icon">⇅</span></th>
      <th onclick="sortPwdTable(1)">File <span class="sort-icon">⇅</span></th>
      <th onclick="sortPwdTable(2)">Line <span class="sort-icon">⇅</span></th>
      <th onclick="sortPwdTable(3)">Type/Rule <span class="sort-icon">⇅</span></th>
      <th>Password</th>
      <th onclick="sortPwdTable(5)">Confidence <span class="sort-icon">⇅</span></th>
      <th></th>
      <th></th>
    </tr>
  </thead>
  <tbody id="pwd-table-body">
{rows_html}
  </tbody>
</table>
</div>"""

        # ── False Positive Exclusions ──
        fp_html = ""
        if fp_findings:
            fp_items = ""
            for fp in fp_findings:
                fp_file = Path(fp.get('file', '')).name
                fp_pattern = fp.get('pattern', fp.get('subtype', 'Unknown'))
                fp_reason = fp.get('fp_reason', 'Encrypted/Framework')
                fp_items += (
                    f'<div class="pwd-excluded-item">'
                    f'<span class="pwd-excluded-reason">{html_mod.escape(fp_reason)}</span>'
                    f'<span class="pwd-excluded-file">{html_mod.escape(fp_file)}</span>'
                    f'<span style="color:var(--text-muted);font-size:0.72rem">{html_mod.escape(fp_pattern)}</span>'
                    f'<span style="color:var(--text-muted);font-size:0.72rem;margin-left:auto;">'
                    f'{html_mod.escape(str(fp.get("match", ""))[:40])}'
                    f'</span>'
                    f'</div>'
                )
            fp_html = f"""
<div class="pwd-excluded" id="pwd-excluded-panel">
  <div class="pwd-excluded-header" onclick="toggleExclusionsPanel()">
    <span class="pwd-excluded-title">🚫 False Positive Exclusions ({len(fp_findings)} items)</span>
    <span class="pwd-excluded-toggle">▼</span>
  </div>
  <div class="pwd-excluded-body">
    {fp_items}
  </div>
</div>"""

        # ── No findings message ──
        if not cred_findings:
            empty_msg = """
<div style="text-align:center;padding:40px 20px;">
  <div style="font-size:3rem;margin-bottom:12px;">✅</div>
  <div style="font-size:1.1rem;font-weight:700;color:var(--success);margin-bottom:6px;">No Credential Findings</div>
  <div style="font-size:0.82rem;color:var(--text-muted);">No hardcoded passwords, API keys, or credential exposures were detected in this package.</div>
</div>"""
            return f"""
<div class="pwd-section-header">
  <div class="pwd-brand">
    <span class="pwd-brand-icon">🔑</span>
    <div>
      <div class="pwd-brand-title">Password Intelligence Engine</div>
      <div class="pwd-brand-sub">Credential exposure analysis &amp; risk assessment</div>
    </div>
  </div>
</div>
{cards_html}
{empty_msg}
{fp_html}"""

        return f"""
<div class="pwd-section-header">
  <div class="pwd-brand">
    <span class="pwd-brand-icon">🔑</span>
    <div>
      <div class="pwd-brand-title">Password Intelligence Engine</div>
      <div class="pwd-brand-sub">Credential exposure analysis &amp; risk assessment</div>
    </div>
  </div>
</div>
{cards_html}
{charts_html}
{filter_html}
{table_html}
{fp_html}"""

    # ------------------------------------------------------------------ #
    #  Section: Executive Summary                                          #
    # ------------------------------------------------------------------ #

    def _section_exec_summary(self) -> str:
        s    = self._summary
        risk = self._risk_score
        cards = [
            ("card-total",    "num-total",    s.get("total_issues", 0), "Total Issues"),
            ("card-critical", "num-critical", s.get("critical", 0),     "Critical"),
            ("card-high",     "num-high",     s.get("high", 0),         "High"),
            ("card-medium",   "num-medium",   s.get("medium", 0),       "Medium"),
            ("card-low",      "num-low",      s.get("low", 0),          "Low"),
            ("card-score",    "num-score",    f"{risk:.1f}",             "Risk Score"),
        ]
        cards_html = "\n".join(
            f'<div class="summary-card {cls}">'
            f'<div class="card-number {num_cls}" data-counter="{num}">{num}</div>'
            f'<div class="card-label">{label}</div>'
            f'</div>'
            for cls, num_cls, num, label in cards
        )
        return f'<div class="summary-grid">{cards_html}</div>'

    # ------------------------------------------------------------------ #
    #  Section: Risk Assessment                                            #
    # ------------------------------------------------------------------ #

    def _section_risk_assessment(self) -> str:
        s    = self._summary
        risk = self._risk_score
        total = max(s.get("total_issues", 1), 1)

        def pct(n):
            return min(100, round((n / total) * 100))

        # Gauge color
        if risk >= 75:
            gauge_color = "#e63946"
        elif risk >= 50:
            gauge_color = "#f4a261"
        elif risk >= 25:
            gauge_color = "#e9c46a"
        else:
            gauge_color = "#2a9d8f"

        # SVG arc gauge (radius=60, cx=cy=70, stroke-dasharray = circumference = 2πr * 270/360)
        r   = 60
        cx  = cy = 70
        circ = 2 * 3.14159 * r * (270 / 360)  # 270° arc
        fill = (risk / 100) * circ
        offset = circ - fill

        gauge_svg = f"""
<svg class="gauge-svg" width="140" height="140" viewBox="0 0 140 140">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#162032" stroke-width="14"
          stroke-dasharray="{circ:.2f} 10000"
          stroke-dashoffset="0"
          transform="rotate(135 {cx} {cy})" stroke-linecap="round"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{gauge_color}" stroke-width="14"
          stroke-dasharray="{fill:.2f} {offset:.2f}"
          id="gauge-fill"
          data-target-dash="{fill:.2f}"
          data-total-dash="{circ:.2f}"
          stroke-dashoffset="0"
          transform="rotate(135 {cx} {cy})" stroke-linecap="round"
          style="stroke-dasharray:0 {circ:.2f}; transition:stroke-dasharray 1.5s ease;"/>
  <text x="{cx}" y="{cy}" text-anchor="middle" fill="{gauge_color}"
        font-size="22" font-weight="800" font-family="Inter, sans-serif"
        dy="0.3em" id="gauge-text">0</text>
  <text x="{cx}" y="{cy + 22}" text-anchor="middle" fill="#8ba0be"
        font-size="8" font-family="Inter, sans-serif">/100</text>
</svg>"""

        bars = [
            ("CRITICAL", "fill-critical", s.get("critical", 0), total),
            ("HIGH",     "fill-high",     s.get("high", 0),     total),
            ("MEDIUM",   "fill-medium",   s.get("medium", 0),   total),
            ("LOW",      "fill-low",      s.get("low", 0),      total),
        ]
        bars_html = "\n".join(
            f"""<div class="risk-bar-row">
              <span class="risk-bar-label">{sev}</span>
              <div class="risk-bar-track">
                <div class="risk-bar-fill {cls}" style="width:0%"
                     data-target-width="{pct(n)}%"></div>
              </div>
              <span class="risk-bar-count">{n}</span>
            </div>"""
            for sev, cls, n, tot in bars
        )

        files_scanned = s.get("files_scanned", 0)
        ps_files      = s.get("ps_files", 0)
        binaries      = s.get("binaries_analyzed", 0)
        duration      = s.get("scan_duration", 0)

        return f"""
<div class="risk-gauge-container">
  {gauge_svg}
  <div class="gauge-details">
    <h3>Risk Distribution</h3>
    {bars_html}
    <div style="margin-top:16px; display:flex; gap:24px; font-size:0.78rem; color:var(--text-muted);">
      <span>📄 {files_scanned} files scanned</span>
      <span>🔷 {ps_files} PowerShell files</span>
      <span>⚙ {binaries} binaries</span>
      <span>⏱ {duration:.2f}s</span>
    </div>
  </div>
</div>"""

    # ------------------------------------------------------------------ #
    #  Section: Compliance Matrix                                          #
    # ------------------------------------------------------------------ #

    def _section_compliance_matrix(self) -> str:
        # Build a set of failing rule_ids from actual issues
        failing_rules = {issue.get("subtype", issue.get("pattern", "")) for issue in self._issues}
        failing_rules |= {issue.get("pattern", "") for issue in self._issues}

        def chip(ctrl_id: str, triggers: List[str]) -> str:
            # Check if any trigger rule has a finding
            failing = any(t in failing_rules for t in triggers)
            if not failing:
                css = "ctrl-pass"
                icon = "✓"
            else:
                css = "ctrl-fail"
                icon = "✗"
            return (
                f'<div class="control-chip {css}" title="{ctrl_id}">'
                f'<span class="ctrl-icon">{icon}</span>'
                f'<span class="ctrl-id">{ctrl_id}</span>'
                f'</div>'
            )

        def framework_section(title: str, controls: List[str]) -> str:
            chips = "".join(
                chip(ctrl, CONTROL_TRIGGERS.get(ctrl, []))
                for ctrl in controls
            )
            return f"""
<div class="compliance-framework">
  <h4>{title}</h4>
  <div class="control-grid">{chips}</div>
</div>"""

        return (
            framework_section("NIST SP 800-53 Rev5", NIST_CONTROLS) +
            framework_section("CMMC 2.0 Level 2", CMMC_CONTROLS) +
            framework_section("CIS Controls v8", CIS_CONTROLS)
        )

    # ------------------------------------------------------------------ #
    #  Section: Findings Explorer                                          #
    # ------------------------------------------------------------------ #

    def _section_findings_explorer(self) -> str:
        # Exclude credential findings (shown in Password Intelligence section)
        cred_rule_ids = self._get_credential_rule_ids()
        non_cred = [
            i for i in self._issues
            if i.get('type') != 'Credential'
            and not (i.get('type') == 'DataLeakage' and i.get('rule_id', '') in cred_rule_ids)
            and i.get('pattern', '') not in cred_rule_ids
            and i.get('subtype', '') not in cred_rule_ids
        ]
        issues  = sorted(non_cred, key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 99))
        counts  = {s: sum(1 for i in issues if i.get("severity") == s)
                   for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        total   = len(issues)

        rows = []
        for idx, issue in enumerate(issues):
            sev      = issue.get("severity", "INFO")
            row_cls  = f"row-{sev.lower()}"
            sev_html = f'<span class="sev-badge sev-{sev}">{sev}</span>'
            file_    = Path(issue.get("file", "")).name
            line_    = issue.get("line", "—")
            pattern  = issue.get("pattern", issue.get("subtype", "—"))
            mitre    = issue.get("mitre_id", "—")
            cwe      = issue.get("cwe_id", "—")
            match_   = (issue.get("match") or "")[:80]
            ctx      = (issue.get("context") or "").replace("<", "&lt;").replace(">", "&gt;")
            rem      = issue.get("remediation", "Review manually")
            itype    = issue.get("type", "—")
            conf     = issue.get("confidence", 0)

            # Compliance tags for this finding
            sub_rule = issue.get("subtype", issue.get("pattern", ""))
            comp_tags = []
            for ctrl, triggers in CONTROL_TRIGGERS.items():
                if sub_rule in triggers or pattern in triggers:
                    comp_tags.append(ctrl)
            tags_html = "".join(f'<span class="compliance-tag">{t}</span>' for t in comp_tags[:6])

            detail_id = f"detail-{idx}"
            row_id    = f"row-{idx}"

            rows.append(f"""
<tr class="finding-row {row_cls}" onclick="toggleDetail('{detail_id}', this)" id="{row_id}"
    data-severity="{sev}" data-type="{itype}">
  <td>{sev_html}</td>
  <td><strong>{file_}</strong><br><small style="color:var(--text-muted)">{itype}</small></td>
  <td style="font-family:monospace;color:var(--text-muted)">{line_}</td>
  <td>{pattern}</td>
  <td style="font-family:monospace;font-size:0.72rem;color:var(--info)">{mitre}</td>
  <td>{cwe}</td>
  <td><span style="color:var(--text-muted);font-size:0.72rem">{conf:.0%}</span></td>
  <td><span class="expand-icon">▼</span></td>
</tr>
<tr class="detail-row hidden" id="{detail_id}">
  <td colspan="8">
    <div class="detail-content">
      <div class="detail-grid">
        <div class="detail-field">
          <label>Match</label>
          <div class="detail-code">{match_}</div>
        </div>
        <div class="detail-field">
          <label>Remediation</label>
          <p>{rem}</p>
        </div>
      </div>
      <div class="detail-field" style="margin-bottom:10px">
        <label>Context</label>
        <div class="detail-code" style="white-space:pre-wrap">{ctx[:400]}</div>
      </div>
      <div class="detail-field">
        <label>Compliance Controls</label>
        <div class="compliance-tags">{tags_html if tags_html else "<span style='color:var(--text-muted)'>None mapped</span>"}</div>
      </div>
    </div>
  </td>
</tr>""")

        rows_html = "\n".join(rows)
        return f"""
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterFindings('ALL', this)">All ({total})</button>
  <button class="filter-btn btn-critical" onclick="filterFindings('CRITICAL', this)">Critical ({counts.get('CRITICAL',0)})</button>
  <button class="filter-btn btn-high"     onclick="filterFindings('HIGH', this)">High ({counts.get('HIGH',0)})</button>
  <button class="filter-btn btn-medium"   onclick="filterFindings('MEDIUM', this)">Medium ({counts.get('MEDIUM',0)})</button>
  <button class="filter-btn btn-low"      onclick="filterFindings('LOW', this)">Low ({counts.get('LOW',0)})</button>
  <span class="filter-count" id="findings-count">Showing {total} findings</span>
</div>
<div class="findings-table-wrap">
<table class="findings-table" id="findings-table">
  <thead>
    <tr>
      <th onclick="sortTable(0)">Severity <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(1)">File / Type <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(2)">Line <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(3)">Pattern <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(4)">MITRE ATT&amp;CK <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(5)">CWE <span class="sort-icon">⇅</span></th>
      <th onclick="sortTable(6)">Confidence <span class="sort-icon">⇅</span></th>
      <th></th>
    </tr>
  </thead>
  <tbody id="findings-body">
{rows_html}
  </tbody>
</table>
</div>"""

    # ------------------------------------------------------------------ #
    #  Section: MITRE ATT&CK Heatmap                                      #
    # ------------------------------------------------------------------ #

    def _section_mitre_heatmap(self) -> str:
        # Count techniques per tactic
        tactic_techs: Dict[str, Dict[str, int]] = {}
        for tactic_id, tactic_name in ATTACK_TACTICS:
            tactic_techs[tactic_name] = {}

        all_technique_ids = set()
        for issue in self._issues:
            tid = issue.get("mitre_id", "")
            if not tid:
                continue
            tactic = TECHNIQUE_TACTIC_MAP.get(tid, "")
            if tactic:
                tactic_techs[tactic][tid] = tactic_techs[tactic].get(tid, 0) + 1
                all_technique_ids.add(tid)

        if not all_technique_ids:
            return '<p style="color:var(--text-muted);font-style:italic;padding:16px 0">No MITRE ATT&amp;CK techniques mapped in current findings.</p>'

        # Only show tactics that have findings
        active_tactics = [(tid, tname) for tid, tname in ATTACK_TACTICS
                          if tactic_techs.get(tname)]

        # Build header row
        header_cells = "".join(
            f'<th title="{tid}">{tname}</th>'
            for tid, tname in active_tactics
        )

        # Build rows per technique
        rows_html = ""
        for tech_id in sorted(all_technique_ids):
            cells = ""
            for _, tname in active_tactics:
                count = tactic_techs[tname].get(tech_id, 0)
                heat = "heat-0" if count == 0 else ("heat-1" if count == 1 else "heat-2")
                label = str(count) if count > 0 else "·"
                cells += f'<td class="{heat}"><span class="technique-id">{tech_id}</span><br>{label}</td>'
            rows_html += f"<tr>{cells}</tr>\n"

        return f"""
<div class="mitre-scroll">
<table class="mitre-table">
  <thead>
    <tr>
      {header_cells}
    </tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>
</div>
<p style="font-size:0.72rem;color:var(--text-muted);margin-top:10px">
  ● Gray = not observed &nbsp;|&nbsp; 🟡 Yellow = 1 occurrence &nbsp;|&nbsp;
  🔴 Red = 2+ occurrences
</p>"""

    # ------------------------------------------------------------------ #
    #  Section: SBOM Inventory                                            #
    # ------------------------------------------------------------------ #

    def _section_sbom(self) -> str:
        if not self.sbom_data:
            return '<p class="sbom-placeholder">SBOM data not available. Run with --format sbom or --format all to include SBOM generation.</p>'

        components = self.sbom_data.get("components", [])
        if not components:
            return '<p class="sbom-placeholder">No components found in SBOM data.</p>'

        # Reuse the SBOMGenerator's HTML renderer if possible, else generate inline
        try:
            from .sbom_generator import SBOMGenerator
            gen = SBOMGenerator.__new__(SBOMGenerator)
            return gen.generate_html_sbom_section(components)
        except Exception:
            pass

        # Fallback inline renderer
        rows = ""
        for comp in components:
            hashes = comp.get("hashes", {})
            sha256 = (hashes.get("SHA-256", "") or "")[:16] + "…"
            vulns  = comp.get("vulnerabilities", [])
            signed = "✔" if comp.get("is_signed") else "✖"
            rows += (
                f"<tr><td>{comp['name']}</td><td>{comp.get('type','file')}</td>"
                f"<td>{comp.get('version','')}</td><td>{comp.get('publisher','')}</td>"
                f"<td><code>{sha256}</code></td><td>{signed}</td><td>{len(vulns)}</td></tr>\n"
            )

        return f"""
<div style="overflow-x:auto; border-radius:10px; border:1px solid var(--border);">
<table class="findings-table">
  <thead>
    <tr>
      <th>Component</th><th>Type</th><th>Version</th><th>Publisher</th>
      <th>SHA-256 (prefix)</th><th>Signed</th><th>CVEs</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</div>"""

    # ------------------------------------------------------------------ #
    #  Section: Approval Workflow                                          #
    # ------------------------------------------------------------------ #

    def _section_workflow(self) -> str:
        if not self.workflow:
            return '<p style="color:var(--text-muted);font-style:italic">Workflow data not available.</p>'

        current = self.workflow.get("current_state", "UNKNOWN")
        history = self.workflow.get("history", [])
        chain_valid = self.workflow.get("chain_valid", None)

        STAGE_ORDER = [
            "PENDING_SCAN", "AUTO_SCAN_PASSED", "ANALYST_REVIEW",
            "ANALYST_APPROVED", "CISO_REVIEW", "CISO_APPROVED", "DEPLOYED",
        ]
        STAGE_ICONS = {
            "PENDING_SCAN":       ("🔄", "Pending"),
            "AUTO_SCAN_PASSED":   ("✔",  "Scan Passed"),
            "AUTO_SCAN_REJECTED": ("✖",  "Scan Rejected"),
            "ANALYST_REVIEW":     ("🔍", "Analyst Review"),
            "ANALYST_APPROVED":   ("✔",  "Analyst Approved"),
            "ANALYST_REJECTED":   ("✖",  "Analyst Rejected"),
            "CISO_REVIEW":        ("👔", "CISO Review"),
            "CISO_APPROVED":      ("✔",  "CISO Approved"),
            "CISO_REJECTED":      ("✖",  "CISO Rejected"),
            "DEPLOYED":           ("🚀", "Deployed"),
        }

        done_states = {r["to_state"] for r in history}
        stages_html = ""
        for stage in STAGE_ORDER:
            icon, label = STAGE_ICONS.get(stage, ("?", stage))
            if stage == current:
                css = "ws-current"
            elif stage in done_states:
                css = "ws-done"
            elif "REJECTED" in stage and stage in done_states:
                css = "ws-rejected"
            else:
                css = ""
            stages_html += (
                f'<div class="workflow-stage {css}">'
                f'<span class="ws-icon">{icon}</span>'
                f'<span class="ws-label">{label}</span>'
                f'</div>'
            )

        chain_badge = ""
        if chain_valid is not None:
            cb_cls = "ctrl-pass" if chain_valid else "ctrl-fail"
            chain_badge = f'<div class="control-chip {cb_cls}" style="margin-bottom:12px">{"✓ Chain Intact" if chain_valid else "✗ Chain Violated"}</div>'

        history_items = ""
        for rec in history:
            ts   = rec.get("timestamp", "")
            frm  = rec.get("from_state", "")
            to   = rec.get("to_state", "")
            actr = rec.get("actor", "System")
            evt  = rec.get("event", "")
            hash_= rec.get("hash", "")[:16]
            history_items += f"""
<div class="audit-entry">
  <div class="audit-meta">
    <span class="audit-time">{ts}</span>
    <span class="audit-actor">{actr}</span>
    <span class="audit-event">{evt}</span>
  </div>
  <div class="audit-detail">{frm} → <strong>{to}</strong> &nbsp;|&nbsp; hash: <code style="font-size:0.7rem;color:#6dffb9">{hash_}…</code></div>
</div>"""

        return f"""
{chain_badge}
<div class="workflow-stage-grid">{stages_html}</div>
<h4 style="font-size:0.82rem;color:var(--text-muted);margin-bottom:12px">State Transition History</h4>
<div class="audit-timeline">{history_items if history_items else '<p style="color:var(--text-muted)">No transitions recorded yet.</p>'}</div>
"""

    # ------------------------------------------------------------------ #
    #  Section: Audit Trail                                                #
    # ------------------------------------------------------------------ #

    def _section_audit_trail(self) -> str:
        audit_log = self.findings.get("audit_log", [])
        if not audit_log:
            return '<p style="color:var(--text-muted);font-style:italic">No audit log entries found.</p>'

        entries_html = ""
        for entry in audit_log:
            ts    = entry.get("timestamp", "")
            actor = entry.get("actor", "System")
            event = entry.get("event", "")
            detail= entry.get("detail", "")
            entries_html += f"""
<div class="audit-entry">
  <div class="audit-meta">
    <span class="audit-time">{ts}</span>
    <span class="audit-actor">{actor}</span>
    <span class="audit-event">{event}</span>
  </div>
  <div class="audit-detail">{detail}</div>
</div>"""

        return f'<div class="audit-timeline">{entries_html}</div>'

    # ------------------------------------------------------------------ #
    #  Section: Remediation Tracker                                        #
    # ------------------------------------------------------------------ #

    def _section_remediation_tracker(self) -> str:
        # Group issues by severity
        groups: Dict[str, List[dict]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []
        }
        for issue in self._issues:
            sev = issue.get("severity", "LOW")
            if sev in groups:
                groups[sev].append(issue)

        html_parts = []
        for sev, issues in groups.items():
            if not issues:
                continue
            items_html = ""
            for issue in issues:
                pattern = issue.get("pattern", issue.get("subtype", "Unknown"))
                file_   = Path(issue.get("file", "")).name
                line_   = issue.get("line", "")
                rem     = issue.get("remediation", "Review manually")
                mitre   = issue.get("mitre_id", "")
                mitre_badge = f'<span class="rem-mitre">{mitre}</span>' if mitre else ""
                items_html += f"""
<div class="rem-item">
  <div class="rem-checkbox" title="Mark complete"></div>
  <div>
    <div class="rem-text"><strong>{pattern}</strong> — {rem}</div>
    <div class="rem-file">{file_}{f" : line {line_}" if line_ else ""} {mitre_badge}</div>
  </div>
</div>"""
            html_parts.append(f"""
<div class="remediation-group rem-{sev.lower()}">
  <h4>{sev} ({len(issues)} item{'s' if len(issues) != 1 else ''})</h4>
  {items_html}
</div>""")

        return "\n".join(html_parts) if html_parts else '<p style="color:var(--success)">✓ No remediation items found.</p>'

    # ------------------------------------------------------------------ #
    #  JavaScript                                                          #
    # ------------------------------------------------------------------ #

    def _javascript(self) -> str:
        risk_score   = self._risk_score
        total_issues = self._summary.get("total_issues", 0)
        critical     = self._summary.get("critical", 0)
        high         = self._summary.get("high", 0)
        medium       = self._summary.get("medium", 0)
        low          = self._summary.get("low", 0)

        return f"""<script>
// ---- Animated counters ----
document.addEventListener('DOMContentLoaded', function() {{
  animateCounters();
  animateGauge();
  animateBars();
  setupNavHighlight();
}});

function animateCounters() {{
  document.querySelectorAll('[data-counter]').forEach(function(el) {{
    var target = parseFloat(el.getAttribute('data-counter'));
    var isFloat = target % 1 !== 0;
    var duration = 1200, start = null, from = 0;
    function step(ts) {{
      if (!start) start = ts;
      var progress = Math.min((ts - start) / duration, 1);
      var ease = 1 - Math.pow(1 - progress, 3);
      var val = from + (target - from) * ease;
      el.textContent = isFloat ? val.toFixed(1) : Math.round(val);
      if (progress < 1) requestAnimationFrame(step);
    }}
    requestAnimationFrame(step);
  }});
}}

function animateGauge() {{
  var fill = document.getElementById('gauge-fill');
  var text = document.getElementById('gauge-text');
  if (!fill || !text) return;
  var targetDash = parseFloat(fill.getAttribute('data-target-dash'));
  var totalDash  = parseFloat(fill.getAttribute('data-total-dash'));
  var target = {risk_score:.1f};
  setTimeout(function() {{
    fill.style.strokeDasharray = targetDash + ' ' + (totalDash - targetDash);
    var start = null, duration = 1500;
    function step(ts) {{
      if (!start) start = ts;
      var p = Math.min((ts - start) / duration, 1);
      var ease = 1 - Math.pow(1 - p, 3);
      text.textContent = (target * ease).toFixed(1);
      if (p < 1) requestAnimationFrame(step);
    }}
    requestAnimationFrame(step);
  }}, 200);
}}

function animateBars() {{
  var bars = document.querySelectorAll('[data-target-width]');
  setTimeout(function() {{
    bars.forEach(function(bar) {{
      bar.style.width = bar.getAttribute('data-target-width');
    }});
  }}, 300);
}}

// ---- Findings filter ----
function filterFindings(severity, btn) {{
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    b.classList.remove('active');
  }});
  btn.classList.add('active');

  var rows = document.querySelectorAll('.finding-row');
  var count = 0;
  rows.forEach(function(row) {{
    if (severity === 'ALL' || row.getAttribute('data-severity') === severity) {{
      row.classList.remove('hidden');
      // also show/hide its detail row
      var detailId = null;
      row.getAttribute('onclick') && (detailId = row.getAttribute('onclick').match(/'([^']+)'/)?.[1]);
      if (detailId) {{
        var detail = document.getElementById(detailId);
        if (detail && !detail.classList.contains('expanded')) detail.classList.add('hidden');
      }}
      count++;
    }} else {{
      row.classList.add('hidden');
      // hide detail rows too
      var detailId = row.getAttribute('onclick') && row.getAttribute('onclick').match(/'([^']+)'/)?.[1];
      if (detailId) {{
        var detail = document.getElementById(detailId);
        if (detail) detail.classList.add('hidden');
      }}
    }}
  }});
  var fc = document.getElementById('findings-count');
  if (fc) fc.textContent = 'Showing ' + count + ' findings';
}}

// ---- Expandable rows ----
function toggleDetail(detailId, row) {{
  var detail = document.getElementById(detailId);
  if (!detail) return;
  var hidden = detail.classList.toggle('hidden');
  row.classList.toggle('expanded', !hidden);
}}

// ---- Table sorting ----
var sortDir = {{}};
function sortTable(col) {{
  var table = document.getElementById('findings-table');
  if (!table) return;
  var tbody = document.getElementById('findings-body');
  var rows = Array.from(tbody.querySelectorAll('.finding-row'));
  var asc = !sortDir[col];
  sortDir[col] = asc;
  var sevOrder = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};
  rows.sort(function(a, b) {{
    var aVal = a.cells[col] ? a.cells[col].textContent.trim() : '';
    var bVal = b.cells[col] ? b.cells[col].textContent.trim() : '';
    if (col === 0) {{
      aVal = sevOrder[a.getAttribute('data-severity')] || 99;
      bVal = sevOrder[b.getAttribute('data-severity')] || 99;
      return asc ? aVal - bVal : bVal - aVal;
    }}
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  }});
  rows.forEach(function(row) {{
    var detailId = row.getAttribute('onclick') && row.getAttribute('onclick').match(/'([^']+)'/)?.[1];
    tbody.appendChild(row);
    if (detailId) {{
      var detail = document.getElementById(detailId);
      if (detail) tbody.appendChild(detail);
    }}
  }});
}}

// ---- Nav highlight on scroll ----
function setupNavHighlight() {{
  var sections = document.querySelectorAll('.report-section[id]');
  var navLinks = document.querySelectorAll('.nav-link');

  var observer = new IntersectionObserver(function(entries) {{
    entries.forEach(function(entry) {{
      if (entry.isIntersecting) {{
        navLinks.forEach(function(link) {{
          link.classList.toggle('active', link.getAttribute('data-section') === entry.target.id);
        }});
      }}
    }});
  }}, {{ rootMargin: '-30% 0px -60% 0px', threshold: 0 }});

  sections.forEach(function(s) {{ observer.observe(s); }});
}}

// ---- Password Intelligence: Toggle password mask ----
function togglePasswordMask(id) {{
  var el = document.getElementById(id);
  if (!el) return;
  if (el.classList.contains('pwd-masked')) {{
    el.textContent = el.getAttribute('data-real');
    el.classList.remove('pwd-masked');
  }} else {{
    el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
    el.classList.add('pwd-masked');
  }}
}}

// ---- Password Intelligence: Expand detail row ----
function togglePwdDetail(detailId, row) {{
  var detail = document.getElementById(detailId);
  if (!detail) return;
  var hidden = detail.classList.toggle('hidden');
  row.classList.toggle('expanded', !hidden);
}}

// ---- Password Intelligence: Filter by severity ----
var pwdActiveFilter = 'ALL';
var pwdActiveType = 'ALL';

function filterCredentials(severity, btn) {{
  pwdActiveFilter = severity;
  document.querySelectorAll('.pwd-filter-btn').forEach(function(b) {{
    b.classList.remove('active');
  }});
  btn.classList.add('active');
  applyPwdFilters();
}}

function filterCredentialsByType(typeName) {{
  pwdActiveType = typeName;
  applyPwdFilters();
}}

function applyPwdFilters() {{
  var rows = document.querySelectorAll('.pwd-row');
  var count = 0;
  rows.forEach(function(row) {{
    var sevMatch = (pwdActiveFilter === 'ALL' || row.getAttribute('data-severity') === pwdActiveFilter);
    var typeMatch = (pwdActiveType === 'ALL' || row.getAttribute('data-credtype') === pwdActiveType);
    if (sevMatch && typeMatch) {{
      row.classList.remove('hidden');
      count++;
    }} else {{
      row.classList.add('hidden');
      var detailId = row.getAttribute('onclick') && row.getAttribute('onclick').match(/'([^']+)'/)?.[1];
      if (detailId) {{
        var detail = document.getElementById(detailId);
        if (detail) detail.classList.add('hidden');
      }}
    }}
  }});
  var fc = document.getElementById('pwd-findings-count');
  if (fc) fc.textContent = 'Showing ' + count + ' credential findings';
}}

// ---- Password Intelligence: Sort table ----
var pwdSortDir = {{}};
function sortPwdTable(col) {{
  var tbody = document.getElementById('pwd-table-body');
  if (!tbody) return;
  var rows = Array.from(tbody.querySelectorAll('.pwd-row'));
  var asc = !pwdSortDir[col];
  pwdSortDir[col] = asc;
  var sevOrder = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};
  rows.sort(function(a, b) {{
    var aVal = a.cells[col] ? a.cells[col].textContent.trim() : '';
    var bVal = b.cells[col] ? b.cells[col].textContent.trim() : '';
    if (col === 0) {{
      aVal = sevOrder[a.getAttribute('data-severity')] || 99;
      bVal = sevOrder[b.getAttribute('data-severity')] || 99;
      return asc ? aVal - bVal : bVal - aVal;
    }}
    if (col === 5) {{
      aVal = parseFloat(aVal) || 0;
      bVal = parseFloat(bVal) || 0;
      return asc ? aVal - bVal : bVal - aVal;
    }}
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  }});
  rows.forEach(function(row) {{
    var detailId = row.getAttribute('onclick') && row.getAttribute('onclick').match(/'([^']+)'/)?.[1];
    tbody.appendChild(row);
    if (detailId) {{
      var detail = document.getElementById(detailId);
      if (detail) tbody.appendChild(detail);
    }}
  }});
}}

// ---- Password Intelligence: Copy file path ----
function copyFilePath(btn, path) {{
  if (navigator.clipboard) {{
    navigator.clipboard.writeText(path).then(function() {{
      btn.classList.add('copied');
      btn.textContent = '✓';
      setTimeout(function() {{
        btn.classList.remove('copied');
        btn.textContent = '\uD83D\uDCCB';
      }}, 1500);
    }});
  }}
}}

// ---- Password Intelligence: Toggle exclusions panel ----
function toggleExclusionsPanel() {{
  var panel = document.getElementById('pwd-excluded-panel');
  if (panel) panel.classList.toggle('expanded');
}}

// ---- Animate Password Intelligence bar charts on load ----
document.addEventListener('DOMContentLoaded', function() {{
  setTimeout(function() {{
    document.querySelectorAll('.pwd-bar-fill[data-target-width]').forEach(function(bar) {{
      bar.style.width = bar.getAttribute('data-target-width');
    }});
  }}, 500);
}});
</script>"""

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def _report_hash(self) -> str:
        payload = json.dumps(self.findings, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
