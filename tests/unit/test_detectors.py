
import pytest
from unittest.mock import MagicMock
from controller.detection.detectors.policy import PolicyDetector
from controller.detection.detectors.rogue import RogueAPDetector
from controller.baseline.models import BaselineProfile
from common.detection.reason_codes import ReasonCodes

def test_policy_detector():
    """Verify static policy checks."""
    detector = PolicyDetector()
    
    # 1. Open Network -> Finding
    telemetry = {"ssid": "OpenNet", "security": "Open", "bssid": "AA:AA:AA:AA:AA:AA"}
    findings = detector.process(telemetry)
    assert len(findings) == 1
    assert findings[0].confidence_raw == 1.0
    assert findings[0].evidence_list[0].type == "configuration"
    
    # 2. WEP Network -> Finding
    telemetry = {"ssid": "OldNet", "security": "WEP", "bssid": "BB:BB:BB:BB:BB:BB"}
    findings = detector.process(telemetry)
    assert len(findings) == 1
    assert "WPA2/3" in findings[0].evidence_list[0].description

    # 3. Secure -> No Finding
    telemetry = {"ssid": "SecureNet", "security": "WPA2", "bssid": "CC:CC:CC:CC:CC:CC"}
    findings = detector.process(telemetry)
    assert len(findings) == 0

def test_rogue_detector():
    """Verify baseline deviations."""
    mock_store = MagicMock()
    detector = RogueAPDetector(baseline_store=mock_store)
    
    # Setup Profile (Normal: Ch 6, Max RSSI -50)
    profile = BaselineProfile(
        features={
            "channels": {"6": 10}, 
            "rssi": {"max": -50}
        }
    )
    mock_store.get_profile.return_value = profile
    
    # 1. Channel Mismatch (Ch 1 vs 6) -> Finding
    telemetry = {
        "ssid": "CorpWiFi", "security": "WPA2", "bssid": "AA:AA",
        "channel": 1, "rssi_dbm": -60
    }
    findings = detector.process(telemetry, context={"site_id": "HQ"})
    assert len(findings) == 1
    assert findings[0].reason_codes[0].code == ReasonCodes.CHANNEL_MISMATCH.code
    
    # 2. RSSI Spike (-30 vs Max -50) -> Finding
    telemetry = {
        "ssid": "CorpWiFi", "security": "WPA2", "bssid": "AA:AA",
        "channel": 6, "rssi_dbm": -30
    }
    findings = detector.process(telemetry, context={"site_id": "HQ"})
    assert len(findings) == 1
    assert findings[0].reason_codes[0].code == ReasonCodes.RSSI_ANOMALY.code

    # 3. Normal Behavior -> No Finding
    telemetry = {
        "ssid": "CorpWiFi", "security": "WPA2", "bssid": "AA:AA",
        "channel": 6, "rssi_dbm": -55
    }
    findings = detector.process(telemetry, context={"site_id": "HQ"})
    assert len(findings) == 0
