
import pytest
from common.scoring.types import RiskScore, Severity
from common.detection.reason_codes import ReasonCodes, ReasonCategory
from controller.scoring.risk import RiskModel

def test_risk_calculation():
    """Verify Risk = Confidence * Impact logic."""
    # 1. High Confidence, High Impact
    # 0.9 * 100 = 90 -> CRITICAL (>80)
    score = RiskModel.calculate(confidence=0.9, impact=100.0)
    assert score.value == 90.0
    assert score.severity == Severity.CRITICAL

    # 2. Medium Confidence, High Impact
    # 0.5 * 100 = 50 -> MEDIUM (>30)
    score = RiskModel.calculate(confidence=0.5, impact=100.0)
    assert score.value == 50.0
    assert score.severity == Severity.MEDIUM

    # 3. Low Confidence, Low Impact
    # 0.2 * 20 = 4 -> LOW (<=30)
    score = RiskModel.calculate(confidence=0.2, impact=20.0)
    assert score.value == 4.0
    assert score.severity == Severity.LOW

    # 4. Boundary Check (High)
    # 0.61 * 100 = 61 -> HIGH (>60)
    score = RiskModel.calculate(confidence=0.61, impact=100.0)
    assert score.severity == Severity.HIGH

def test_clamping():
    """Verify values are clamped."""
    # Over 1.0 confidence -> treated as 1.0
    score = RiskModel.calculate(confidence=1.5, impact=100.0)
    assert score.value == 100.0
    
    # Negative impact -> treated as 0.0
    score = RiskModel.calculate(confidence=1.0, impact=-50.0)
    assert score.value == 0.0

def test_reason_codes():
    """Verify Reason Code catalog and formatting."""
    # 1. Check constants
    rc = ReasonCodes.SSID_SPOOFING
    assert rc.code == "SSID_SPOOFING"
    assert rc.category == ReasonCategory.THREAT
    
    # 2. Check formatting
    msg = rc.format(ssid="CorpWiFi", bssid="AA:BB:CC:DD:EE:FF")
    assert "SSID 'CorpWiFi'" in msg
    assert "BSSID 'AA:BB:CC:DD:EE:FF'" in msg

def test_severity_enum():
    """Verify Severity string representations exist."""
    assert Severity.CRITICAL == "critical"
    assert Severity.LOW == "low"
