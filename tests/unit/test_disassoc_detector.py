#!/usr/bin/env python3
"""
Tests for DisassocFloodDetector.
"""

import time

import pytest

from algos.disassoc_detector import DisassocConfig, DisassocFloodDetector


class TestDisassocFloodDetector:
    """Tests for the Disassociation Flood Detector."""

    def _make_frame(self, bssid="AA:BB:CC:11:22:33", client="DD:EE:FF:00:11:22"):
        return {
            "frame_type": "disassoc",
            "frame_subtype": "disassoc",
            "bssid": bssid,
            "mac_dst": client,
        }

    def test_no_alert_below_threshold(self):
        """Rate below threshold should not trigger alert."""
        config = DisassocConfig(rate_threshold=10.0, window_seconds=5.0)
        det = DisassocFloodDetector(config=config)

        # Only 3 frames — well below 10/sec threshold
        for _ in range(3):
            result = det.ingest(self._make_frame())
        assert result is None

    def test_alert_on_flood(self):
        """Rate above threshold should trigger alert."""
        config = DisassocConfig(
            rate_threshold=5.0, window_seconds=2.0, cooldown_seconds=0.0
        )
        det = DisassocFloodDetector(config=config)

        alerts = []
        for _ in range(20):
            r = det.ingest(self._make_frame())
            if r:
                alerts.append(r)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["alert_type"] == "disassoc_flood"
        assert alert["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert alert["mitre_attack"] == "T1499.001"

    def test_cooldown_prevents_duplicate_alerts(self):
        """Cooldown should prevent consecutive alerts for same pair."""
        config = DisassocConfig(
            rate_threshold=5.0, window_seconds=2.0, cooldown_seconds=300.0
        )
        det = DisassocFloodDetector(config=config)

        alerts = []
        for _ in range(50):
            r = det.ingest(self._make_frame())
            if r:
                alerts.append(r)

        # Should only get 1 alert due to long cooldown
        assert len(alerts) == 1

    def test_ignores_non_disassoc_frames(self):
        """Should not process non-disassoc frames."""
        det = DisassocFloodDetector()

        result = det.ingest(
            {
                "frame_type": "beacon",
                "frame_subtype": "beacon",
                "bssid": "AA:BB:CC:11:22:33",
            }
        )
        assert result is None

    def test_severity_escalation_with_multiple_clients(self):
        """Severity should escalate when multiple clients are targeted."""
        config = DisassocConfig(
            rate_threshold=5.0,
            window_seconds=2.0,
            cooldown_seconds=0.0,
            min_unique_clients=3,
        )
        det = DisassocFloodDetector(config=config)

        # Send frames targeting 5 different clients
        alerts = []
        for i in range(5):
            client_mac = f"CC:DD:EE:FF:00:{i:02X}"
            for _ in range(15):
                r = det.ingest(self._make_frame(client=client_mac))
                if r:
                    alerts.append(r)

        assert len(alerts) >= 1
        # Later alerts should have higher severity due to multiple clients
        last_alert = alerts[-1]
        assert last_alert["severity"] in ("HIGH", "CRITICAL")
        assert last_alert["evidence"]["unique_clients_targeted"] >= 3

    def test_alert_evidence_fields(self):
        """Alert should contain all expected evidence fields."""
        config = DisassocConfig(
            rate_threshold=5.0, window_seconds=2.0, cooldown_seconds=0.0
        )
        det = DisassocFloodDetector(config=config)

        alert = None
        for _ in range(20):
            r = det.ingest(self._make_frame())
            if r and alert is None:
                alert = r

        assert alert is not None
        assert "frame_count" in alert["evidence"]
        assert "rate_per_sec" in alert["evidence"]
        assert "window_seconds" in alert["evidence"]
        assert "is_broadcast" in alert["evidence"]
        assert "unique_clients_targeted" in alert["evidence"]

    def test_broadcast_detection(self):
        """Broadcast disassoc should be flagged as broadcast."""
        config = DisassocConfig(
            rate_threshold=5.0, window_seconds=2.0, cooldown_seconds=0.0
        )
        det = DisassocFloodDetector(config=config)

        alert = None
        for _ in range(20):
            r = det.ingest(self._make_frame(client="ff:ff:ff:ff:ff:ff"))
            if r and alert is None:
                alert = r

        assert alert is not None
        assert alert["evidence"]["is_broadcast"] is True

    def test_stats(self):
        """Stats should reflect current state."""
        det = DisassocFloodDetector()
        det.ingest(self._make_frame())

        stats = det.get_stats()
        assert stats["tracked_pairs"] >= 1
        assert stats["total_recent_frames"] >= 1

    def test_reset(self):
        """Reset should clear all state."""
        det = DisassocFloodDetector()
        det.ingest(self._make_frame())
        det.reset()

        stats = det.get_stats()
        assert stats["tracked_pairs"] == 0
        assert stats["alerts_generated"] == 0
