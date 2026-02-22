#!/usr/bin/env python3
"""
Tests for BeaconFloodDetector.
"""

import time

import pytest

from algos.beacon_flood_detector import BeaconFloodConfig, BeaconFloodDetector


class TestBeaconFloodDetector:
    """Tests for the Beacon Flood Detector."""

    def _make_beacon(self, ssid="TestNet", bssid="AA:BB:CC:11:22:33"):
        return {
            "frame_type": "beacon",
            "frame_subtype": "beacon",
            "ssid": ssid,
            "bssid": bssid,
        }

    def test_no_alert_below_threshold(self):
        """Few unique SSIDs should not trigger alert."""
        config = BeaconFloodConfig(unique_ssid_threshold=50, time_window=30)
        det = BeaconFloodDetector(config=config)

        for i in range(10):
            result = det.ingest(self._make_beacon(ssid=f"Net-{i}"))
        assert result is None

    def test_alert_on_mass_ssids(self):
        """Many unique SSIDs should trigger alert."""
        config = BeaconFloodConfig(
            unique_ssid_threshold=20, time_window=60, cooldown_seconds=0
        )
        det = BeaconFloodDetector(config=config)

        alerts = []
        for i in range(30):
            bssid = f"DE:AD:BE:EF:{i:02X}:00"
            r = det.ingest(self._make_beacon(ssid=f"FakeNet-{i}", bssid=bssid))
            if r:
                alerts.append(r)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["alert_type"] == "beacon_flood"
        assert alert["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert alert["mitre_attack"] == "T1498.001"

    def test_ignores_non_beacon_frames(self):
        """Should not process non-beacon frames."""
        det = BeaconFloodDetector()
        result = det.ingest(
            {
                "frame_type": "data",
                "frame_subtype": "data",
                "bssid": "AA:BB:CC:11:22:33",
            }
        )
        assert result is None

    def test_cooldown_prevents_spam(self):
        """Cooldown should prevent rapid re-alerting."""
        config = BeaconFloodConfig(
            unique_ssid_threshold=10, time_window=60, cooldown_seconds=300
        )
        det = BeaconFloodDetector(config=config)

        alerts = []
        for batch in range(3):
            for i in range(20):
                idx = batch * 20 + i
                bssid = f"DE:AD:{idx:02X}:00:00:00"
                r = det.ingest(self._make_beacon(ssid=f"Net-{idx}", bssid=bssid))
                if r:
                    alerts.append(r)

        # Long cooldown should limit to 1 alert
        assert len(alerts) == 1

    def test_severity_escalation_with_bssid_diversity(self):
        """High BSSID diversity should escalate severity."""
        config = BeaconFloodConfig(
            unique_ssid_threshold=10,
            min_unique_bssids=5,
            time_window=60,
            cooldown_seconds=0,
        )
        det = BeaconFloodDetector(config=config)

        alerts = []
        for i in range(50):
            bssid = f"DE:AD:BE:EF:{i:02X}:00"
            r = det.ingest(self._make_beacon(ssid=f"Fake-{i}", bssid=bssid))
            if r:
                alerts.append(r)

        assert len(alerts) >= 1
        # With many unique BSSIDs + SSIDs, should be HIGH or CRITICAL
        alert = alerts[0]
        assert alert["severity"] in ("HIGH", "CRITICAL")

    def test_alert_evidence_fields(self):
        """Alert should contain all expected evidence fields."""
        config = BeaconFloodConfig(
            unique_ssid_threshold=10, time_window=60, cooldown_seconds=0
        )
        det = BeaconFloodDetector(config=config)

        alert = None
        for i in range(15):
            bssid = f"AA:BB:CC:{i:02X}:00:00"
            r = det.ingest(self._make_beacon(ssid=f"Net-{i}", bssid=bssid))
            if r and alert is None:
                alert = r

        assert alert is not None
        assert "unique_ssid_count" in alert["evidence"]
        assert "unique_bssid_count" in alert["evidence"]
        assert "beacon_rate_per_sec" in alert["evidence"]
        assert "oui_prefix_count" in alert["evidence"]
        assert "sample_ssids" in alert["evidence"]
        assert alert["evidence"]["unique_ssid_count"] >= 10

    def test_hidden_ssids_not_counted(self):
        """Empty SSIDs (hidden networks) should not be counted."""
        config = BeaconFloodConfig(unique_ssid_threshold=5, time_window=60)
        det = BeaconFloodDetector(config=config)

        for _ in range(10):
            det.ingest(self._make_beacon(ssid=""))

        stats = det.get_stats()
        assert stats["tracked_ssids"] == 0

    def test_stats(self):
        """Stats should reflect current state."""
        det = BeaconFloodDetector()
        det.ingest(self._make_beacon(ssid="Net1"))
        det.ingest(self._make_beacon(ssid="Net2", bssid="11:22:33:44:55:66"))

        stats = det.get_stats()
        assert stats["tracked_ssids"] == 2
        assert stats["tracked_bssids"] == 2

    def test_reset(self):
        """Reset should clear all state."""
        det = BeaconFloodDetector()
        det.ingest(self._make_beacon())
        det.reset()

        stats = det.get_stats()
        assert stats["tracked_ssids"] == 0
        assert stats["tracked_bssids"] == 0
        assert stats["alerts_generated"] == 0
