"""
Sentinel NetLab - Risk Scoring Engine
======================================
Rule-based risk assessment with ML-ready feature extraction.

Methodology:
1. Rule-based detection with weighted scoring
2. Anomaly detection via statistical baselines
3. Temporal analysis for attack patterns
4. Aggregated risk score: 0-100 scale

Risk Levels:
- CLEAN (0-20): Normal network activity
- LOW (21-40): Minor anomalies, monitoring
- SUSPICIOUS (41-60): Potential threat, investigate
- HIGH_RISK (61-80): Likely attack, alert
- CRITICAL (81-100): Active attack, immediate action
"""

import statistics
import time
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    """Risk assessment levels"""

    CLEAN = "clean"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


@dataclass
class RiskFactor:
    """Individual risk factor contributing to score"""

    name: str
    description: str
    weight: float  # 0.0 - 1.0
    score: float  # 0 - 100 (before weight applied)
    evidence: dict = field(default_factory=dict)
    mitre_id: str | None = None

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight


@dataclass
class RiskAssessment:
    """Complete risk assessment for a network/entity"""

    entity_id: str  # BSSID or MAC
    timestamp: float

    # Scores
    total_score: float
    risk_level: RiskLevel
    confidence: float  # 0.0 - 1.0

    # Contributing factors
    factors: list[RiskFactor] = field(default_factory=list)

    # Recommendations
    actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "timestamp": self.timestamp,
            "total_score": round(self.total_score, 2),
            "risk_level": self.risk_level.value,
            "confidence": round(self.confidence, 2),
            "factors": [
                {
                    "name": f.name,
                    "description": f.description,
                    "score": round(f.weighted_score, 2),
                    "mitre_id": f.mitre_id,
                }
                for f in self.factors
            ],
            "actions": self.actions,
        }


# =============================================================================
# RISK RULES
# =============================================================================


class RiskRule:
    """Base class for risk detection rules"""

    def __init__(
        self,
        name: str,
        description: str,
        weight: float = 1.0,
        base_score: float = 50.0,
        mitre_id: str | None = None,
    ):
        self.name = name
        self.description = description
        self.weight = weight
        self.base_score = base_score
        self.mitre_id = mitre_id

    def evaluate(self, context: dict) -> RiskFactor | None:
        """Evaluate rule against context, return factor if triggered"""
        raise NotImplementedError


class DeauthFloodRule(RiskRule):
    """Detect deauthentication flood attacks"""

    def __init__(self):
        super().__init__(
            name="deauth_flood",
            description="High volume of deauthentication frames detected",
            weight=0.9,
            base_score=80.0,
            mitre_id="T1498",
        )
        self.threshold = 10  # frames per second

    def evaluate(self, context: dict) -> RiskFactor | None:
        deauth_count = context.get("deauth_count", 0)
        window_sec = context.get("window_seconds", 60)

        if window_sec == 0:
            return None

        rate = deauth_count / window_sec

        if rate >= self.threshold or deauth_count >= self.threshold:
            # Score based on whichever is higher relative to threshold
            metric = max(rate, deauth_count / 5.0)  # heuristic scaling
            score = min(100, self.base_score + (metric - self.threshold) * 2)
            return RiskFactor(
                name=self.name,
                description=self.description,
                weight=self.weight,
                score=score,
                evidence={
                    "deauth_count": deauth_count,
                    "rate_per_sec": round(rate, 2),
                    "threshold": self.threshold,
                },
                mitre_id=self.mitre_id,
            )
        return None


class EvilTwinRule(RiskRule):
    """Detect evil twin / rogue AP attacks"""

    def __init__(self):
        super().__init__(
            name="evil_twin",
            description="Multiple BSSIDs broadcasting same SSID",
            weight=0.95,
            base_score=90.0,
            mitre_id="T1557.001",
        )

    def evaluate(self, context: dict) -> RiskFactor | None:
        ssid_bssid_map = context.get("ssid_bssid_map", {})

        for ssid, bssids in ssid_bssid_map.items():
            if len(bssids) > 1:
                return RiskFactor(
                    name=self.name,
                    description=f"SSID '{ssid}' has {len(bssids)} different BSSIDs",
                    weight=self.weight,
                    score=self.base_score,
                    evidence={
                        "ssid": ssid,
                        "bssid_count": len(bssids),
                        "bssids": list(bssids)[:5],  # Limit for display
                    },
                    mitre_id=self.mitre_id,
                )
        return None


class RSSIAnomalyRule(RiskRule):
    """Detect sudden RSSI changes (potential evil twin)"""

    def __init__(self):
        super().__init__(
            name="rssi_anomaly",
            description="Sudden signal strength change detected",
            weight=0.6,
            base_score=50.0,
        )
        self.threshold_db = 20  # dB change threshold

    def evaluate(self, context: dict) -> RiskFactor | None:
        rssi_history = context.get("rssi_history", [])

        if len(rssi_history) < 2:
            return None

        # Check for sudden changes
        for i in range(1, len(rssi_history)):
            delta = abs(rssi_history[i] - rssi_history[i - 1])
            if delta >= self.threshold_db:
                return RiskFactor(
                    name=self.name,
                    description=f"RSSI changed by {delta} dB",
                    weight=self.weight,
                    score=min(100, self.base_score + delta),
                    evidence={
                        "delta_db": delta,
                        "previous": rssi_history[i - 1],
                        "current": rssi_history[i],
                    },
                )
        return None


class SequenceAnomalyRule(RiskRule):
    """Detect sequence number anomalies (replay attacks)"""

    def __init__(self):
        super().__init__(
            name="sequence_anomaly",
            description="Frame sequence number anomaly detected",
            weight=0.7,
            base_score=60.0,
            mitre_id="T1040",
        )

    def evaluate(self, context: dict) -> RiskFactor | None:
        seq_numbers = context.get("sequence_numbers", [])

        if len(seq_numbers) < 3:
            return None

        # Check for resets or large jumps
        anomalies = 0
        for i in range(1, len(seq_numbers)):
            expected_next = (seq_numbers[i - 1] + 1) % 4096
            if seq_numbers[i] != expected_next:
                # Allow small skips due to missed frames
                diff = (seq_numbers[i] - seq_numbers[i - 1]) % 4096
                if diff > 10 or seq_numbers[i] < seq_numbers[i - 1]:
                    anomalies += 1

        if anomalies > 2:
            return RiskFactor(
                name=self.name,
                description=f"Detected {anomalies} sequence anomalies",
                weight=self.weight,
                score=min(100, self.base_score + anomalies * 5),
                evidence={
                    "anomaly_count": anomalies,
                    "sequence_samples": seq_numbers[:10],
                },
                mitre_id=self.mitre_id,
            )
        return None


class WeakSecurityRule(RiskRule):
    """Flag networks with weak security"""

    def __init__(self):
        super().__init__(
            name="weak_security",
            description="Network uses weak or no encryption",
            weight=0.5,
            base_score=40.0,
        )
        self.weak_types = {"open", "wep", "wpa"}

    def evaluate(self, context: dict) -> RiskFactor | None:
        security_type = context.get("security_type", "unknown")

        if security_type in self.weak_types:
            scores = {"open": 60, "wep": 50, "wpa": 30}
            return RiskFactor(
                name=self.name,
                description=f"Network uses {security_type} security",
                weight=self.weight,
                score=scores.get(security_type, self.base_score),
                evidence={"security_type": security_type},
            )
        return None


# =============================================================================
# RISK ENGINE
# =============================================================================


class RiskEngine:
    """
    Risk scoring engine with pluggable rules.

    Usage:
        engine = RiskEngine()
        engine.add_rule(DeauthFloodRule())
        engine.add_rule(EvilTwinRule())

        assessment = engine.assess(bssid, context)
        print(f"Risk: {assessment.risk_level} ({assessment.total_score})")
    """

    def __init__(self):
        self.rules: list[RiskRule] = []
        self.baselines: dict[str, dict] = {}  # Entity baselines

    def add_rule(self, rule: RiskRule) -> None:
        """Add detection rule"""
        self.rules.append(rule)

    def remove_rule(self, name: str) -> None:
        """Remove rule by name"""
        self.rules = [r for r in self.rules if r.name != name]

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score <= 20:
            return RiskLevel.CLEAN
        elif score <= 40:
            return RiskLevel.LOW
        elif score <= 60:
            return RiskLevel.SUSPICIOUS
        elif score <= 80:
            return RiskLevel.HIGH_RISK
        else:
            return RiskLevel.CRITICAL

    @staticmethod
    def _level_to_actions(level: RiskLevel) -> list[str]:
        """Get recommended actions for risk level"""
        actions = {
            RiskLevel.CLEAN: [],
            RiskLevel.LOW: ["Monitor", "Update baseline"],
            RiskLevel.SUSPICIOUS: ["Investigate", "Notify analyst"],
            RiskLevel.HIGH_RISK: ["Alert", "Capture evidence", "Prepare containment"],
            RiskLevel.CRITICAL: [
                "Immediate alert",
                "Isolate if possible",
                "Incident response",
            ],
        }
        return actions.get(level, [])

    def assess(self, entity_id: str, context: dict) -> RiskAssessment:
        """
        Assess risk for an entity given context.

        Args:
            entity_id: BSSID, MAC, or other identifier
            context: Dict with frame stats, history, etc.

        Returns:
            RiskAssessment with score, level, and factors
        """
        factors = []

        # Evaluate all rules
        for rule in self.rules:
            try:
                factor = rule.evaluate(context)
                if factor is not None:
                    factors.append(factor)
            except Exception:  # nosec B110
                # Log but don't fail
                pass

        # Calculate total score (sum of weighted scores, capped at 100)
        if factors:
            total_score = min(100, sum(f.weighted_score for f in factors))
        else:
            total_score = 0.0

        # Determine risk level
        risk_level = self._score_to_level(total_score)

        # Calculate confidence based on evidence quality
        confidence = self._calculate_confidence(factors, context)

        # Get recommended actions
        actions = self._level_to_actions(risk_level)

        return RiskAssessment(
            entity_id=entity_id,
            timestamp=time.time(),
            total_score=total_score,
            risk_level=risk_level,
            confidence=confidence,
            factors=factors,
            actions=actions,
        )

    def _calculate_confidence(self, factors: list[RiskFactor], context: dict) -> float:
        """Calculate confidence in assessment"""
        if not factors:
            return 1.0  # High confidence in "clean"

        # More evidence = higher confidence
        evidence_count = sum(len(f.evidence) for f in factors)
        frame_count = context.get("frame_count", 0)

        # Base confidence
        confidence = 0.5

        # Boost for more evidence
        if evidence_count > 5:
            confidence += 0.2
        if frame_count > 100:
            confidence += 0.2

        # Boost for multiple corroborating rules
        if len(factors) >= 2:
            confidence += 0.1

        return min(1.0, confidence)

    def update_baseline(self, entity_id: str, metrics: dict) -> None:
        """Update statistical baseline for an entity"""
        if entity_id not in self.baselines:
            self.baselines[entity_id] = {
                "rssi_values": [],
                "frame_count": 0,
                "first_seen": time.time(),
            }

        baseline = self.baselines[entity_id]

        # Update RSSI history
        if "rssi" in metrics:
            baseline["rssi_values"].append(metrics["rssi"])
            # Keep last 100 values
            baseline["rssi_values"] = baseline["rssi_values"][-100:]

        baseline["frame_count"] += metrics.get("frame_count", 1)
        baseline["last_seen"] = time.time()

    def get_baseline_stats(self, entity_id: str) -> dict:
        """Get baseline statistics for an entity"""
        if entity_id not in self.baselines:
            return {}

        baseline = self.baselines[entity_id]
        rssi_values = baseline.get("rssi_values", [])

        stats = {
            "first_seen": baseline.get("first_seen"),
            "last_seen": baseline.get("last_seen"),
            "frame_count": baseline.get("frame_count", 0),
        }

        if rssi_values:
            stats["rssi_mean"] = statistics.mean(rssi_values)
            stats["rssi_stdev"] = (
                statistics.stdev(rssi_values) if len(rssi_values) > 1 else 0
            )

        return stats


# =============================================================================
# DEFAULT ENGINE
# =============================================================================


def create_default_engine() -> RiskEngine:
    """Create engine with all default rules"""
    engine = RiskEngine()
    engine.add_rule(DeauthFloodRule())
    engine.add_rule(EvilTwinRule())
    engine.add_rule(RSSIAnomalyRule())
    engine.add_rule(SequenceAnomalyRule())
    engine.add_rule(WeakSecurityRule())
    return engine
