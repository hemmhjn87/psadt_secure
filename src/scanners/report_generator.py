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
        output_path.write_text(html, encoding="utf-8")
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
            <h1 class="report-title">DEFENSE-GRADE PACKAGE SECURITY SCANNER</h1>
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
        <h2 class="section-title"><span class="section-icon">🔍</span> Findings Explorer</h2>
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

/* ---- Print styles ---- */
@media print {
  :root { --primary: #fff; --surface: #f5f7fa; --text: #111; --accent: #0a1628; --border: #ccc; }
  .status-banner { position: static; color-adjust: exact; print-color-adjust: exact; }
  .sidebar { display: none; }
  .main-content { margin-left: 0; padding: 20px; }
  .app-layout { display: block; }
  .report-section { page-break-inside: avoid; }
  .summary-card, .control-chip { border: 1px solid #ccc !important; }
  .filter-bar, .filter-btn { display: none; }
  .findings-table tr.hidden { display: table-row !important; }
  .detail-row.hidden { display: table-row !important; }
  .gauge-svg { display: none; }
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
            ("sec-risk",       "🎯", "Risk Assessment"),
            ("sec-compliance", "📋", "Compliance Matrix"),
            ("sec-hemspect",   "⚡", "HemSpect™ Engine"),
            ("sec-findings",   "🔍", "Findings Explorer"),
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
        issues  = sorted(self._issues, key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 99))
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
</script>"""

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def _report_hash(self) -> str:
        payload = json.dumps(self.findings, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
