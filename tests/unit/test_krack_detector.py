#!/usr/bin/env python3
"""
Tests for KRACKDetector.
"""

import time

import pytest

from algos.krack_detector import HandshakeState, KRACKConfig, KRACKDetector


class TestKRACKDetector:
    """Tests for the KRACK (Key Reinstallation) Detector."""

    def _make_eapol(self, bssid="AA:BB:CC:11:22:33", src="", dst="", msg=1):
        """Create an EAPOL frame with the given message number."""
        return {
            "frame_type": "eapol",
            "bssid": bssid,
            "src_addr": src,
            "dst_addr": dst,
            "eapol_message": msg,
        }

    def test_normal_handshake_no_alert(self):
        """Normal 4-way handshake (M1→M2→M3→M4) should not trigger alert."""
        det = KRACKDetector()
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        # M1: AP -> Client
        assert det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=1)) is None
        # M2: Client -> AP
        assert det.ingest(self._make_eapol(ap, src=client, dst=ap, msg=2)) is None
        # M3: AP -> Client (single)
        assert det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3)) is None
        # M4: Client -> AP
        assert det.ingest(self._make_eapol(ap, src=client, dst=ap, msg=4)) is None

    def test_excessive_m3_retransmission_alert(self):
        """Multiple M3 retransmissions should trigger alert."""
        config = KRACKConfig(
            m3_retransmit_threshold=3, time_window=30, cooldown_seconds=0
        )
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        # M1
        det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=1))
        # M2
        det.ingest(self._make_eapol(ap, src=client, dst=ap, msg=2))

        # Send M3 multiple times (retransmissions)
        alerts = []
        for _ in range(5):
            r = det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))
            if r:
                alerts.append(r)

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["alert_type"] == "krack_attack"
        assert alert["severity"] in ("HIGH", "CRITICAL")
        assert alert["evidence"]["attack_subtype"] == "excessive_m3_retransmission"
        assert alert["evidence"]["m3_count"] >= 3
        assert alert["mitre_attack"] == "T1557.002"

    def test_m3_after_m4_replay_alert(self):
        """M3 after M4 should trigger definitive replay alert."""
        config = KRACKConfig(
            m3_retransmit_threshold=100,  # High threshold so only M3-after-M4 triggers
            m3_after_m4_alert=True,
            cooldown_seconds=0,
        )
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        # Complete normal handshake
        det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=1))
        det.ingest(self._make_eapol(ap, src=client, dst=ap, msg=2))
        det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))
        det.ingest(self._make_eapol(ap, src=client, dst=ap, msg=4))

        # Now send M3 again — this is the replay
        result = det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))

        assert result is not None
        assert result["alert_type"] == "krack_attack"
        assert result["severity"] == "CRITICAL"
        assert result["evidence"]["attack_subtype"] == "m3_replay_after_m4"
        assert result["evidence"]["cve"] == "CVE-2017-13077"

    def test_cooldown_prevents_duplicate_alerts(self):
        """Cooldown should prevent consecutive alerts."""
        config = KRACKConfig(m3_retransmit_threshold=3, cooldown_seconds=300)
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        alerts = []
        for _ in range(10):
            r = det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))
            if r:
                alerts.append(r)

        # Long cooldown should limit to 1 alert
        assert len(alerts) == 1

    def test_ignores_non_eapol_frames(self):
        """Should not process non-EAPOL frames."""
        det = KRACKDetector()
        result = det.ingest(
            {
                "frame_type": "beacon",
                "bssid": "AA:BB:CC:11:22:33",
            }
        )
        assert result is None

    def test_multi_client_tracking(self):
        """Should track handshakes per (AP, client) pair independently."""
        config = KRACKConfig(m3_retransmit_threshold=3, cooldown_seconds=0)
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client1 = "11:11:11:11:11:11"
        client2 = "22:22:22:22:22:22"

        # M3 flood to client1
        alerts = []
        for _ in range(5):
            r = det.ingest(self._make_eapol(ap, src=ap, dst=client1, msg=3))
            if r:
                alerts.append(r)

        assert len(alerts) >= 1
        assert alerts[0]["evidence"]["client_mac"] == client1

        # Different client — should be tracked separately
        r = det.ingest(self._make_eapol(ap, src=ap, dst=client2, msg=3))
        # Only 1 M3 for client2, shouldn't alert yet
        assert r is None

    def test_alert_evidence_fields(self):
        """Alert should contain all expected evidence fields."""
        config = KRACKConfig(m3_retransmit_threshold=3, cooldown_seconds=0)
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        alert = None
        for _ in range(5):
            r = det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))
            if r and alert is None:
                alert = r

        assert alert is not None
        ev = alert["evidence"]
        assert "attack_subtype" in ev
        assert "client_mac" in ev
        assert "m3_count" in ev
        assert "m1_count" in ev
        assert "m4_count" in ev
        assert "cve" in ev
        assert ev["cve"] == "CVE-2017-13077"

    def test_severity_critical_on_high_m3_count(self):
        """Very high M3 count should trigger CRITICAL severity."""
        config = KRACKConfig(m3_retransmit_threshold=3, cooldown_seconds=0)
        det = KRACKDetector(config=config)
        ap = "AA:BB:CC:11:22:33"
        client = "DD:EE:FF:00:11:22"

        alert = None
        # Send threshold * 2 M3 frames to trigger CRITICAL
        for _ in range(8):
            r = det.ingest(self._make_eapol(ap, src=ap, dst=client, msg=3))
            if r:
                alert = r  # Keep the latest as it has the highest m3_count

        assert alert is not None
        # Second alert (at 6+ M3s) should be CRITICAL since >= threshold*2
        assert alert["severity"] == "CRITICAL"

    def test_stats(self):
        """Stats should reflect current state."""
        det = KRACKDetector()
        det.ingest(
            self._make_eapol(msg=3, src="AA:BB:CC:11:22:33", dst="DD:EE:FF:00:11:22")
        )

        stats = det.get_stats()
        assert stats["tracked_handshakes"] >= 1

    def test_reset(self):
        """Reset should clear all state."""
        det = KRACKDetector()
        det.ingest(
            self._make_eapol(msg=3, src="AA:BB:CC:11:22:33", dst="DD:EE:FF:00:11:22")
        )
        det.reset()

        stats = det.get_stats()
        assert stats["tracked_handshakes"] == 0
        assert stats["alerts_generated"] == 0
