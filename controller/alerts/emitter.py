import logging
from datetime import UTC, datetime

from common.detection.evidence import Finding
from common.scoring.types import RiskScore
from controller.dedup.fingerprint import generate_fingerprint
from controller.dedup.policy import TriagePolicy
from controller.dedup.store import EventStore
from controller.models import Alert, get_session
from controller.scoring.risk import RiskModel

logger = logging.getLogger(__name__)


class AlertEmitter:
    """
    Orchestrates the emission of findings into Alerts.
    Applies Deduplication and Suppression.
    """

    def __init__(self, event_store: EventStore, policy: TriagePolicy):
        self.store = event_store
        self.policy = policy

    def process_findings(self, findings: list[Finding], sensor_id: str):
        """
        Process findings -> Triage -> Persist Alert if needed.
        """
        session = get_session()

        for finding in findings:
            # 1. Fingerprint
            fp = generate_fingerprint(finding)

            # 2. Score
            # Assuming Finding came with raw confidence. We calculate Risk.
            # Default impact? Ideally Finding has impact, or we derive from ReasonCode.
            # Simplified: Use Finding.confidence_raw and hardcoded impact for now,
            # Or assume Finding has context.
            # Let's assume Finding has reasons, reason has category/risk.

            # For this phase, let's just calc risk based on conf (0-1.0) and fixed impact 50.0
            # unless we have smarter logic.
            # Better: Get severity from ReasonCode (High/Crit) and map to Impact?

            impact = 50.0  # Default Medium
            if finding.reason_codes:
                cat = finding.reason_codes[0].category
                if "threat" in cat.lower():
                    impact = 90.0
                elif "configuration" in cat.lower():
                    impact = 40.0

            risk_score = RiskModel.calculate(finding.confidence_raw, impact)

            # 3. Triage
            current_state = self.store.get_state(fp)
            should_emit = self.policy.should_emit(
                finding, current_state, risk_score.severity, risk_score.value
            )

            # 4. Update State
            self.store.update_state(
                fp, risk_score.severity, risk_score.value, emitted=should_emit
            )

            if should_emit:
                self._persist_alert(session, finding, risk_score, sensor_id)

        session.close()

    def _persist_alert(
        self, session, finding: Finding, risk: "RiskScore", sensor_id: str
    ):
        """Save Alert to DB."""
        try:
            # Generate Alert ID
            import uuid

            alert_id = str(uuid.uuid4().hex)[:32]

            # Map Reason Codes to JSON
            reasons_json = [
                {"code": r.code, "msg": r.message_template}
                for r in finding.reason_codes
            ]

            alert = Alert(
                id=alert_id,
                sensor_id=sensor_id,
                alert_type=finding.detector_id,
                severity=risk.severity.value,
                title=f"Detection: {finding.reason_codes[0].code}"
                if finding.reason_codes
                else "Unknown Detection",
                description=finding.evidence_list[0].description
                if finding.evidence_list
                else "",
                bssid=finding.entity_key.split("|")[-1]
                if "|" in finding.entity_key
                else None,  # Heuristic
                # ssid not easily extracted from entity key without parsing, assume evidence has it?
                # skipping optional fields for matching minimal schema
                evidence=[e.to_dict() for e in finding.evidence_list],
                reason_codes=reasons_json,
                confidence=finding.confidence_raw,
                impact=float(risk.value / finding.confidence_raw)
                if finding.confidence_raw > 0
                else 0,  # Reverse calc impact?
                risk_score=risk.value,
                created_at=datetime.now(UTC),
            )

            session.add(alert)
            session.commit()
            logger.info(f"Emitted Alert {alert_id} (Risk: {risk.value})")

        except Exception as e:
            logger.error(f"Failed to persist alert: {e}")
            session.rollback()
