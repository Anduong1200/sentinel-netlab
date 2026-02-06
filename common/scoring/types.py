
from dataclasses import dataclass
from enum import StrEnum

# Type aliases for clarity and potential validation later
# Confidence: 0.0 to 1.0 representing probability/certainty
Confidence = float

# Impact: 0.0 to 100.0 representing potential damage/criticality
Impact = float

# Risk: 0.0 to 100.0 derived from Confidence * Impact
Risk = float

class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score > 80:
            return cls.CRITICAL
        elif score > 60:
            return cls.HIGH
        elif score > 30:
            return cls.MEDIUM
        return cls.LOW

@dataclass(frozen=True)
class RiskScore:
    value: Risk
    severity: Severity

    @classmethod
    def calculate(cls, confidence: Confidence, impact: Impact) -> "RiskScore":
        """
        Calculate risk score from confidence and impact.
        Risk = Confidence * Impact
        """
        # Clamp values loosely (strict validation can be done in models)
        c = max(0.0, min(1.0, confidence))
        i = max(0.0, min(100.0, impact))

        score = c * i
        return cls(value=score, severity=Severity.from_score(score))
