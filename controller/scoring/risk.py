from common.scoring.types import Confidence, Impact, RiskScore, Severity


class RiskModel:
    """
    Core Risk Calculation Logic.
    Risk = Confidence * Impact

    Weights:
    - Confidence (0.0 - 1.0): Probability finding is real.
      - 1.0: Deterministic (Policy Violation)
      - 0.8: Strong Heuristic (Baseline Deviation)
      - 0.5: Weak Heuristic

    - Impact (0 - 100): Business/Security consequence.
      - 90+: Active Threat (Rogue AP, MitM)
      - 40-60: Configuration Issue (Open Net)

    Output Risk (0-100) maps to Severity:
    - 90+: CRITICAL
    - 70-89: HIGH
    - 40-69: MEDIUM
    - <40: LOW
    """

    @staticmethod
    def calculate(confidence: Confidence, impact: Impact) -> RiskScore:
        """
        Compute risk score and severity.

        Args:
            confidence: 0.0 to 1.0
            impact: 0.0 to 100.0

        Returns:
            RiskScore object with value and severity
        """
        return RiskScore.calculate(confidence, impact)

    @staticmethod
    def classify_severity(score: float) -> Severity:
        """Expose severity classification logic directly."""
        return Severity.from_score(score)
