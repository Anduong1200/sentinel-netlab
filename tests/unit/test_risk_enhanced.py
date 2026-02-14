"""
Tests for EnhancedRiskScorer (algos/risk.py).
Validates scoring range, monotonicity, boundary, and clamping after the P0 scale fix.
"""

import pytest

from algos.risk import EnhancedRiskScorer


@pytest.fixture
def scorer():
    """Create scorer with defaults (no external YAML)."""
    return EnhancedRiskScorer(config_path="__nonexistent__")


# ---------------------------------------------------------------------------
# Boundary tests
# ---------------------------------------------------------------------------


class TestBoundary:
    def test_zero_risk_for_trusted(self, scorer):
        """Whitelisted + no deviation → score exactly 0."""
        scorer.whitelist = {"TrustedNet"}
        result = scorer.calculate_risk(
            {"ssid": "TrustedNet", "bssid": "00:11:22:33:44:55"},
            deviation_score=0.0,
        )
        assert result["risk_score"] == 0
        assert result["risk_level"] == "Trusted"

    def test_max_risk_capped_at_100(self, scorer):
        """Even extreme inputs should never exceed 100."""
        # All features maxed + high deviation
        net = {
            "ssid": "Free_WiFi_Evil",
            "bssid": "FF:FF:FF:FF:FF:FF",
            "encryption": "Open",
            "signal": -20,
            "channel": 14,
            "vendor": "Unknown",
            "handshake_captured": True,
            "wps_enabled": True,
            "beacon_interval": 9999,
        }
        result = scorer.calculate_risk(net, deviation_score=1.0)
        assert 0 <= result["risk_score"] <= 100

    def test_score_within_range(self, scorer):
        """Any normal network should produce score in [0, 100]."""
        net = {
            "ssid": "CoffeeShop",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "encryption": "WPA2",
            "signal": -65,
            "channel": 6,
        }
        result = scorer.calculate_risk(net)
        assert 0 <= result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# Monotonicity tests
# ---------------------------------------------------------------------------


class TestMonotonicity:
    def test_higher_deviation_higher_risk(self, scorer):
        """Increasing deviation score should not decrease risk."""
        net = {
            "ssid": "TestNet",
            "bssid": "AA:BB:CC:00:00:01",
            "encryption": "WPA2",
            "signal": -60,
        }
        score_low = scorer.calculate_risk(net, deviation_score=0.0)["risk_score"]
        score_high = scorer.calculate_risk(net, deviation_score=0.5)["risk_score"]
        assert score_high >= score_low

    def test_open_enc_higher_than_wpa3(self, scorer):
        """Open encryption should score >= WPA3."""
        base = {"ssid": "TestNet", "bssid": "AA:BB:CC:00:00:01", "signal": -60}
        open_score = scorer.calculate_risk({**base, "encryption": "Open"})["risk_score"]
        wpa3_score = scorer.calculate_risk({**base, "encryption": "WPA3"})["risk_score"]
        assert open_score >= wpa3_score


# ---------------------------------------------------------------------------
# Scale sanity — the core P0 regression test
# ---------------------------------------------------------------------------


class TestScaleSanity:
    def test_moderate_risk_not_saturated(self, scorer):
        """
        A WPA2 network with no special flags should NOT score 100.
        Before the fix, the double ×100 caused almost everything to be 100.
        """
        net = {
            "ssid": "NormalOffice",
            "bssid": "00:11:22:33:44:55",
            "encryption": "WPA2",
            "signal": -50,
            "channel": 6,
            "vendor": "Cisco",
        }
        result = scorer.calculate_risk(net)
        assert result["risk_score"] < 80, (
            f"WPA2 network should not have extreme risk, got {result['risk_score']}"
        )

    def test_open_network_reasonable_range(self, scorer):
        """Open network (unknown) should score moderate, not max."""
        net = {
            "ssid": "Airport_Free",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "encryption": "Open",
            "signal": -45,
            "channel": 6,
            "vendor": "Unknown",
        }
        result = scorer.calculate_risk(net)
        # Should be elevated but not saturated at 100
        assert 10 <= result["risk_score"] <= 80, (
            f"Open network score out of expected range: {result['risk_score']}"
        )

    def test_legacy_score_method(self, scorer):
        """The legacy .score() method should return same as risk_score."""
        net = {
            "ssid": "TestNet",
            "bssid": "AA:BB:CC:00:00:02",
            "encryption": "WPA2",
            "signal": -55,
        }
        legacy = scorer.score(net)
        full = scorer.calculate_risk(net)["risk_score"]
        assert legacy == full


# ---------------------------------------------------------------------------
# Risk level classification
# ---------------------------------------------------------------------------


class TestRiskLevel:
    def test_risk_levels_exist(self, scorer):
        """Risk level should always be one of the expected values."""
        for enc in ("Open", "WEP", "WPA", "WPA2", "WPA3"):
            net = {
                "ssid": "Test",
                "bssid": "00:00:00:00:00:01",
                "encryption": enc,
                "signal": -50,
            }
            result = scorer.calculate_risk(net)
            assert result["risk_level"] in ("Low", "Medium", "High", "Trusted")
