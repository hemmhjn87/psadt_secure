#!/usr/bin/env python3
"""
HemSpect Approval Workflow
3-stage approval: AUTO_SCAN → ANALYST_REVIEW → CISO_APPROVAL
Provides digital chain-of-custody for deployment authorization.

State Machine:
  PENDING_SCAN
    → AUTO_SCAN_PASSED  (0 critical, 0 high)
    → ANALYST_REVIEW    (review required)
    → AUTO_SCAN_REJECTED (rejected)
  AUTO_SCAN_PASSED / ANALYST_REVIEW
    → ANALYST_APPROVED  (analyst clears all issues)
    → ANALYST_REJECTED  (analyst confirms blockers)
    → CISO_REVIEW       (high-risk items accepted)
  CISO_REVIEW
    → CISO_APPROVED
    → CISO_REJECTED
  CISO_APPROVED / ANALYST_APPROVED
    → DEPLOYED
"""

import os
import json
import hashlib
import logging
import socket
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  State definitions                                                   #
# ------------------------------------------------------------------ #

class WorkflowState:
    PENDING_SCAN        = "PENDING_SCAN"
    AUTO_SCAN_REJECTED  = "AUTO_SCAN_REJECTED"
    AUTO_SCAN_PASSED    = "AUTO_SCAN_PASSED"
    ANALYST_REVIEW      = "ANALYST_REVIEW"
    ANALYST_APPROVED    = "ANALYST_APPROVED"
    ANALYST_REJECTED    = "ANALYST_REJECTED"
    CISO_REVIEW         = "CISO_REVIEW"
    CISO_APPROVED       = "CISO_APPROVED"
    CISO_REJECTED       = "CISO_REJECTED"
    DEPLOYED            = "DEPLOYED"


# Valid transitions: { current_state: [allowed_next_states] }
VALID_TRANSITIONS: Dict[str, List[str]] = {
    WorkflowState.PENDING_SCAN:       [WorkflowState.AUTO_SCAN_PASSED,
                                        WorkflowState.ANALYST_REVIEW,
                                        WorkflowState.AUTO_SCAN_REJECTED],
    WorkflowState.AUTO_SCAN_PASSED:   [WorkflowState.ANALYST_APPROVED,
                                        WorkflowState.ANALYST_REJECTED,
                                        WorkflowState.CISO_REVIEW],
    WorkflowState.ANALYST_REVIEW:     [WorkflowState.ANALYST_APPROVED,
                                        WorkflowState.ANALYST_REJECTED,
                                        WorkflowState.CISO_REVIEW],
    WorkflowState.AUTO_SCAN_REJECTED: [WorkflowState.ANALYST_REVIEW],  # escalation path
    WorkflowState.ANALYST_APPROVED:   [WorkflowState.DEPLOYED],
    WorkflowState.ANALYST_REJECTED:   [WorkflowState.ANALYST_REVIEW],  # re-review after fix
    WorkflowState.CISO_REVIEW:        [WorkflowState.CISO_APPROVED,
                                        WorkflowState.CISO_REJECTED],
    WorkflowState.CISO_APPROVED:      [WorkflowState.DEPLOYED],
    WorkflowState.CISO_REJECTED:      [WorkflowState.ANALYST_REVIEW],  # escalation path
    WorkflowState.DEPLOYED:           [],
}


class WorkflowViolationError(Exception):
    """Raised when an illegal state transition is attempted."""
    pass


# ------------------------------------------------------------------ #
#  ApprovalWorkflow                                                    #
# ------------------------------------------------------------------ #

class ApprovalWorkflow:
    """
    3-stage approval workflow with cryptographic hash chain for tamper evidence.
    Persists state to workflow_state.json in the output directory.
    """

    STATE_FILE = "workflow_state.json"
    AUTH_FILE  = "deployment_authorization.json"

    def __init__(self, package_path: Path, output_dir: Path):
        self.package_path = Path(package_path)
        self.output_dir   = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._state_path = self.output_dir / self.STATE_FILE

        # Load existing state or bootstrap
        if self._state_path.exists():
            try:
                with open(self._state_path, "r", encoding="utf-8") as fh:
                    self._state = json.load(fh)
                logger.info("Resumed workflow at state: %s", self._state["current_state"])
            except Exception as exc:
                logger.warning("Could not load workflow state (%s); resetting.", exc)
                self._state = self._bootstrap()
        else:
            self._state = self._bootstrap()
            self.save_state()

    # ---------------------------------------------------------------- #
    #  Public methods                                                   #
    # ---------------------------------------------------------------- #

    def record_scan_result(self, findings: dict) -> str:
        """
        Called after an automated scan completes.
        Transitions PENDING_SCAN → AUTO_SCAN_PASSED | ANALYST_REVIEW | AUTO_SCAN_REJECTED.
        Returns the new state string.
        """
        self._require_state(WorkflowState.PENDING_SCAN)

        summary = findings.get("summary", {})
        approval_status = summary.get("approval_status", "REVIEW_REQUIRED")
        critical = summary.get("critical", 0)
        high     = summary.get("high", 0)

        if approval_status == "APPROVED" and critical == 0 and high == 0:
            new_state = WorkflowState.AUTO_SCAN_PASSED
        elif approval_status == "REJECTED":
            new_state = WorkflowState.AUTO_SCAN_REJECTED
        else:
            new_state = WorkflowState.ANALYST_REVIEW

        event_data = {
            "approval_status": approval_status,
            "critical":  critical,
            "high":      summary.get("high", 0),
            "medium":    summary.get("medium", 0),
            "low":       summary.get("low", 0),
            "risk_score": findings.get("risk_score", 0),
            "scanner_version": findings.get("scanner_version", ""),
            "operator":  findings.get("operator", self._operator()),
        }

        self._transition(new_state, actor="AutoScanner", event="scan_complete", data=event_data)
        self._notify_webhook("scan_complete", {
            "package": self.package_path.name,
            "state":   new_state,
            "summary": event_data,
        })
        return new_state

    def analyst_review(
        self,
        analyst_name: str,
        disposition: Dict[str, dict],
        notes: str,
    ) -> str:
        """
        Record analyst disposition of each finding.
        disposition = { finding_id: { status: "TP"|"FP"|"ACCEPTED_RISK", notes: str } }

        Transitions:
          - All blockers cleared → ANALYST_APPROVED
          - Any TP blocker remains → ANALYST_REJECTED
          - Any ACCEPTED_RISK (high-severity) → CISO_REVIEW
        """
        self._require_state(
            WorkflowState.AUTO_SCAN_PASSED,
            WorkflowState.ANALYST_REVIEW,
            WorkflowState.AUTO_SCAN_REJECTED,
            WorkflowState.CISO_REJECTED,
        )

        accepted_risk_count = sum(
            1 for v in disposition.values() if v.get("status") == "ACCEPTED_RISK"
        )
        confirmed_tp_count = sum(
            1 for v in disposition.values() if v.get("status") == "TP"
        )

        # Digital signature: hash of (disposition + analyst + timestamp)
        ts = self._utcnow()
        sig_payload = json.dumps({
            "disposition":   disposition,
            "analyst_name":  analyst_name,
            "timestamp":     ts,
        }, sort_keys=True).encode("utf-8")
        signature = hashlib.sha256(sig_payload).hexdigest()

        if accepted_risk_count > 0:
            new_state = WorkflowState.CISO_REVIEW
        elif confirmed_tp_count > 0:
            new_state = WorkflowState.ANALYST_REJECTED
        else:
            new_state = WorkflowState.ANALYST_APPROVED

        event_data = {
            "analyst_name":       analyst_name,
            "notes":              notes,
            "disposition_count":  len(disposition),
            "fp_count":           sum(1 for v in disposition.values() if v.get("status") == "FP"),
            "tp_count":           confirmed_tp_count,
            "accepted_risk_count": accepted_risk_count,
            "analyst_signature":  signature,
            "disposition":        disposition,
        }

        self._transition(new_state, actor=analyst_name, event="analyst_review", data=event_data)
        self._notify_webhook("analyst_review", {
            "package":       self.package_path.name,
            "state":         new_state,
            "analyst":       analyst_name,
            "accepted_risk": accepted_risk_count,
        })
        return new_state

    def ciso_approval(
        self,
        ciso_name: str,
        decision: str,
        authorization_number: str,
        notes: str,
    ) -> str:
        """
        CISO final approval gate.
        decision: "APPROVE" or "REJECT"
        Returns new state.
        """
        self._require_state(WorkflowState.CISO_REVIEW)

        decision = decision.upper().strip()
        if decision not in ("APPROVE", "REJECT"):
            raise ValueError(f"Invalid CISO decision: {decision!r}. Must be APPROVE or REJECT.")

        ts = self._utcnow()
        sig_payload = json.dumps({
            "ciso_name":            ciso_name,
            "decision":             decision,
            "authorization_number": authorization_number,
            "timestamp":            ts,
        }, sort_keys=True).encode("utf-8")
        signature = hashlib.sha256(sig_payload).hexdigest()

        new_state = (
            WorkflowState.CISO_APPROVED if decision == "APPROVE"
            else WorkflowState.CISO_REJECTED
        )

        event_data = {
            "ciso_name":            ciso_name,
            "decision":             decision,
            "authorization_number": authorization_number,
            "notes":                notes,
            "ciso_signature":       signature,
        }

        self._transition(new_state, actor=ciso_name, event="ciso_approval", data=event_data)

        if new_state == WorkflowState.CISO_APPROVED:
            self._generate_deployment_authorization(
                ciso_name=ciso_name,
                authorization_number=authorization_number,
                notes=notes,
                ciso_signature=signature,
            )

        self._notify_webhook("ciso_approval", {
            "package":   self.package_path.name,
            "state":     new_state,
            "ciso":      ciso_name,
            "auth_num":  authorization_number,
            "decision":  decision,
        })
        return new_state

    def get_workflow_summary(self) -> dict:
        """Return full workflow history with tamper-evident hash chain."""
        return {
            "package":       self.package_path.name,
            "current_state": self._state["current_state"],
            "created_at":    self._state.get("created_at"),
            "last_updated":  self._state.get("last_updated"),
            "history":       self._state.get("history", []),
            "chain_valid":   self._verify_chain(),
            "chain_tip":     self._state.get("chain_tip", ""),
        }

    def save_state(self):
        """Persist workflow state to disk."""
        with open(self._state_path, "w", encoding="utf-8") as fh:
            json.dump(self._state, fh, indent=2)
        logger.debug("Workflow state saved (%s).", self._state["current_state"])

    # ---------------------------------------------------------------- #
    #  Internal helpers                                                  #
    # ---------------------------------------------------------------- #

    def _bootstrap(self) -> dict:
        now = self._utcnow()
        return {
            "current_state": WorkflowState.PENDING_SCAN,
            "package":       self.package_path.name,
            "package_path":  str(self.package_path),
            "created_at":    now,
            "last_updated":  now,
            "history":       [],
            "chain_tip":     "",
        }

    def _transition(self, new_state: str, actor: str, event: str, data: dict):
        current = self._state["current_state"]
        allowed = VALID_TRANSITIONS.get(current, [])
        if new_state not in allowed:
            raise WorkflowViolationError(
                f"Cannot transition from {current!r} to {new_state!r}. "
                f"Allowed: {allowed}"
            )

        ts = self._utcnow()
        prev_hash = self._state.get("chain_tip", "")

        record = {
            "from_state":  current,
            "to_state":    new_state,
            "actor":       actor,
            "event":       event,
            "timestamp":   ts,
            "data":        data,
            "prev_hash":   prev_hash,
        }

        # Compute hash of this record for the chain
        record_bytes = json.dumps(record, sort_keys=True).encode("utf-8")
        record_hash  = hashlib.sha256(record_bytes).hexdigest()
        record["hash"] = record_hash

        self._state["current_state"] = new_state
        self._state["last_updated"]  = ts
        self._state["chain_tip"]     = record_hash
        self._state["history"].append(record)
        self.save_state()
        logger.info("Workflow transition: %s → %s (actor=%s)", current, new_state, actor)

    def _require_state(self, *states: str):
        current = self._state["current_state"]
        if current not in states:
            raise WorkflowViolationError(
                f"Operation requires state in {states!r}, but current state is {current!r}."
            )

    def _verify_chain(self) -> bool:
        """Verify the integrity of the hash chain in the history."""
        history = self._state.get("history", [])
        prev_hash = ""
        for record in history:
            # Re-compute expected hash
            rec_copy = {k: v for k, v in record.items() if k != "hash"}
            rec_copy["prev_hash"] = prev_hash
            rec_bytes = json.dumps(rec_copy, sort_keys=True).encode("utf-8")
            expected  = hashlib.sha256(rec_bytes).hexdigest()
            if expected != record.get("hash"):
                logger.error("Chain integrity failure at record: %s", record.get("timestamp"))
                return False
            prev_hash = record["hash"]
        return True

    def _generate_deployment_authorization(
        self,
        ciso_name: str,
        authorization_number: str,
        notes: str,
        ciso_signature: str,
    ):
        """Write deployment_authorization.json with full chain summary."""
        summary = self.get_workflow_summary()
        auth_doc = {
            "document_type":        "PSADT_DEPLOYMENT_AUTHORIZATION",
            "format_version":       "1.0",
            "package":              self.package_path.name,
            "package_path":         str(self.package_path),
            "authorization_number": authorization_number,
            "issued_by":            ciso_name,
            "issued_at":            self._utcnow(),
            "ciso_signature":       ciso_signature,
            "notes":                notes,
            "workflow_chain_valid": summary["chain_valid"],
            "workflow_history":     summary["history"],
            "authorized_for":       "PRODUCTION_DEPLOYMENT",
            "compliance_statement": (
                "This authorization was generated following a 3-stage security review "
                "process compliant with NIST SP 800-53 Rev5 SA-11 and CMMC 2.0 "
                "requirements. Chain of custody is cryptographically verifiable."
            ),
        }
        auth_path = self.output_dir / self.AUTH_FILE
        with open(auth_path, "w", encoding="utf-8") as fh:
            json.dump(auth_doc, fh, indent=2)
        logger.info("Deployment authorization written to %s", auth_path)

    def _notify_webhook(self, event: str, data: dict):
        """POST event data to PSADT_WEBHOOK_URL if configured. Silently fails."""
        webhook_url = os.environ.get("PSADT_WEBHOOK_URL", "").strip()
        if not webhook_url:
            return
        try:
            import urllib.request
            payload = json.dumps({
                "event":     event,
                "timestamp": self._utcnow(),
                "data":      data,
            }).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                logger.info("Webhook %s delivered (HTTP %d).", event, resp.status)
        except Exception as exc:
            logger.warning("Webhook delivery failed for event %s: %s", event, exc)

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _operator() -> str:
        return os.environ.get(
            "PSADT_SCAN_OPERATOR",
            os.environ.get("USERNAME", socket.gethostname())
        )
