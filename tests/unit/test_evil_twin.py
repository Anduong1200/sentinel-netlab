#!/usr/bin/env python3
"""
Unit Tests for AdvancedEvilTwinDetector.
The detector is 700+ lines but previously had no dedicated unit tests
(only regression tests via annotated PCAP manifests).
"""

import time

import pytest

from algos.evil_twin import AdvancedEvilTwinDetector, EvilTwinConfig


class TestAdvancedEvilTwinDetector:
    """Unit tests for the Evil Twin Detector."""

    def _make_telemetry(
        self,
        bssid="AA:BB:CC:11:22:33",
        ssid="CorpNet",
        channel=6,
        rssi=-65,
        vendor_oui=None,
        security=None,
        sensor_id="test-sensor",
    ):
        vendor = vendor_oui or bssid[:8]
        tel = {
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "rssi_dbm": rssi,
            "vendor_oui": vendor,
            "sensor_id": sensor_id,
        }
        if security:
            tel["capabilities"] = {"privacy": security != "OPEN"}
            if security == "WPA2":
                tel["rsn_info"] = {"akm": ["PSK"]}
        return tel

    def test_single_ap_no_alert(self):
        """Single AP should never trigger Evil Twin alert."""
        config = EvilTwinConfig(confirmation_window_seconds=0)
        det = AdvancedEvilTwinDetector(config)

        for _ in range(10):
            alerts = det.ingest(self._make_telemetry())
        assert alerts == []

    def test_duplicate_ssid_triggers_alert(self):
        """Two APs with same SSID but different BSSID should trigger."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        # Build history for legitimate AP
        for _ in range(5):
            det.ingest(
                self._make_telemetry(
                    bssid="AA:BB:CC:11:22:33",
                    ssid="CorpNet",
                    vendor_oui="AA:BB:CC",
                )
            )

        # Inject Evil Twin with different BSSID and vendor
        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
                ssid="CorpNet",
                vendor_oui="DE:AD:BE",
                rssi=-35,
            )
        )

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.ssid == "CorpNet"
        assert "DUPLICATE_SSID" in alert.reason_codes
        assert alert.severity in ("MEDIUM", "HIGH", "CRITICAL")

    def test_vendor_mismatch_increases_score(self):
        """Vendor OUI mismatch should increase score."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        # Legitimate AP with vendor AA:BB:CC
        for _ in range(5):
            det.ingest(self._make_telemetry(vendor_oui="AA:BB:CC"))

        # Evil twin with different vendor
        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
                vendor_oui="DE:AD:BE",
            )
        )

        assert len(alerts) >= 1
        assert "VENDOR_MISMATCH" in alerts[0].reason_codes

    def test_rssi_delta_detection(self):
        """Strong signal delta should increase score and appear in reason codes."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
            rssi_delta_threshold=10,
        )
        det = AdvancedEvilTwinDetector(config)

        # Legitimate AP at -65 dBm
        for _ in range(5):
            det.ingest(self._make_telemetry(rssi=-65))

        # Evil twin much stronger at -30 dBm (+35 dB delta)
        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
                rssi=-30,
            )
        )

        assert len(alerts) >= 1
        # Check for STRONGER_SIGNAL reason code
        has_signal = any("STRONGER_SIGNAL" in rc for rc in alerts[0].reason_codes)
        assert has_signal

    def test_confirmation_window_delays_alert(self):
        """With confirmation window > 0, first detection should be pending."""
        config = EvilTwinConfig(
            confirmation_window_seconds=60,  # Long window
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        for _ in range(5):
            det.ingest(self._make_telemetry())

        # First sighting — should start confirmation, not alert
        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
            )
        )

        # Score is likely below 90 (just duplicate SSID + new AP = ~25),
        # so it should be pending
        # Low score first detection goes to pending
        assert len(alerts) == 0
        assert len(det.pending_alerts) >= 1

    def test_immediate_alert_on_critical_score_or_zero_window(self):
        """Score >= 90 or confirmation_window = 0 should alert immediately."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        for _ in range(5):
            det.ingest(self._make_telemetry())

        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
                vendor_oui="DE:AD:BE",
            )
        )

        # With confirmation_window=0, should always alert immediately
        assert len(alerts) >= 1

    def test_multiple_ssids_tracked_independently(self):
        """Different SSIDs should be tracked independently."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        # Two legitimate APs on different SSIDs
        for _ in range(3):
            det.ingest(self._make_telemetry(ssid="NetA", bssid="11:11:11:11:11:11"))
            det.ingest(self._make_telemetry(ssid="NetB", bssid="22:22:22:22:22:22"))

        # Evil twin on NetA — should alert
        alerts_a = det.ingest(
            self._make_telemetry(
                ssid="NetA",
                bssid="FF:FF:FF:FF:FF:FF",
                vendor_oui="FF:FF:FF",
            )
        )
        assert len(alerts_a) >= 1
        assert alerts_a[0].ssid == "NetA"

    def test_alert_has_mitre_mapping(self):
        """Alert should include MITRE ATT&CK references."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        for _ in range(3):
            det.ingest(self._make_telemetry())

        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
            )
        )

        assert len(alerts) >= 1
        assert alerts[0].mitre_technique == "T1557.002"
        assert alerts[0].mitre_tactic == "Credential Access"

    def test_alert_id_format(self):
        """Alert ID should follow ET-YYYYMMDDHHMMSS-NNNN format."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        for _ in range(3):
            det.ingest(self._make_telemetry())

        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
            )
        )

        assert len(alerts) >= 1
        assert alerts[0].alert_id.startswith("ET-")

    def test_stats(self):
        """Stats should reflect tracked state."""
        det = AdvancedEvilTwinDetector()

        det.ingest(self._make_telemetry(ssid="Net1", bssid="11:11:11:11:11:11"))
        det.ingest(self._make_telemetry(ssid="Net2", bssid="22:22:22:22:22:22"))

        stats = det.get_stats()
        assert stats["tracked_aps"] == 2
        assert stats["tracked_ssids"] == 2

    def test_evidence_contains_profiles(self):
        """Alert evidence should contain original and suspect profiles."""
        config = EvilTwinConfig(
            confirmation_window_seconds=0,
            min_duplicate_count=2,
        )
        det = AdvancedEvilTwinDetector(config)

        for _ in range(3):
            det.ingest(self._make_telemetry())

        alerts = det.ingest(
            self._make_telemetry(
                bssid="DE:AD:BE:EF:00:01",
            )
        )

        assert len(alerts) >= 1
        evidence = alerts[0].evidence
        assert "original_bssid" in evidence
        assert "suspect_bssid" in evidence
        assert "rssi_delta" in evidence
        assert "duplicate_count" in evidence
