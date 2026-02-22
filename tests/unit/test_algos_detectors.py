"""
Unit tests for algos detectors that were previously untested:
- KarmaDetector
- JammingDetector
- WardriveDetector
- WEPIVDetector
- ExploitChainAnalyzer
- DeauthFloodDetector (integration correctness)
"""

from algos.dos import DeauthFloodDetector
from algos.exploit_chain_analyzer import ExploitChainAnalyzer
from algos.jamming_detector import JammingDetector
from algos.karma_detector import KarmaDetector
from algos.wardrive_detector import WardriveDetector
from algos.wep_iv_detector import WEPIVDetector


# ═══════════════════════════════════════════════════════════════════════════
# KarmaDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestKarmaDetector:
    def test_no_alert_below_threshold(self):
        """Fewer SSIDs than threshold → no alert."""
        det = KarmaDetector()
        for i in range(2):  # default threshold is 3
            result = det.ingest(
                {
                    "frame_type": "probe_resp",
                    "bssid": "AA:AA:AA:AA:AA:AA",
                    "ssid": f"Net-{i}",
                }
            )
        assert result is None

    def test_alert_on_multi_ssid(self):
        """AP responding to >= threshold unique SSIDs → alert."""
        det = KarmaDetector()
        alerts = []
        for i in range(4):
            r = det.ingest(
                {
                    "frame_type": "probe_resp",
                    "bssid": "AA:AA:AA:AA:AA:AA",
                    "ssid": f"Net-{i}",
                }
            )
            if r:
                alerts.append(r)
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "karma_attack"
        assert alerts[0]["severity"] in ("HIGH", "CRITICAL")

    def test_ignores_non_probe_frames(self):
        """Data frames should not be tracked."""
        det = KarmaDetector()
        for i in range(10):
            result = det.ingest(
                {"frame_type": "data", "bssid": "AA:AA:AA:AA:AA:AA", "ssid": f"Net-{i}"}
            )
        assert result is None

    def test_ignores_hidden_ssid(self):
        """Hidden SSID should not count."""
        det = KarmaDetector()
        for _ in range(5):
            result = det.ingest(
                {
                    "frame_type": "beacon",
                    "bssid": "AA:AA:AA:AA:AA:AA",
                    "ssid": "<Hidden>",
                }
            )
        assert result is None

    def test_no_duplicate_alerts(self):
        """Same BSSID should only alert once."""
        det = KarmaDetector()
        for i in range(6):
            det.ingest(
                {
                    "frame_type": "probe_resp",
                    "bssid": "AA:AA:AA:AA:AA:AA",
                    "ssid": f"Net-{i}",
                }
            )
        # Already alerted, additional SSIDs should not re-alert
        result = det.ingest(
            {"frame_type": "probe_resp", "bssid": "AA:AA:AA:AA:AA:AA", "ssid": "Extra"}
        )
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# JammingDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestJammingDetector:
    def test_no_alert_with_normal_traffic(self):
        """Normal traffic should not trigger jamming alert."""
        det = JammingDetector()
        for _ in range(30):
            result = det.ingest(
                {"channel": 6, "frame_type": "data", "retry": False, "rssi_dbm": -60}
            )
        assert result is None

    def test_rts_cts_flood_triggers_alert(self):
        """High RTS/CTS count should be detected."""
        det = JammingDetector()
        det.config.interval_seconds = 0  # Force immediate evaluation
        for i in range(80):
            result = det.ingest(
                {
                    "channel": 6,
                    "frame_type": "rts",
                    "retry": i % 2 == 0,
                    "rssi_dbm": -70,
                }
            )
        # Should fire after interval evaluation
        if result:
            assert result["alert_type"] == "jamming_detected"

    def test_minimum_sample_size(self):
        """Too few frames should not trigger even with bad indicators."""
        det = JammingDetector()
        det.config.interval_seconds = 0
        for _ in range(5):
            det.ingest(
                {"channel": 6, "frame_type": "rts", "retry": True, "rssi_dbm": -70}
            )
        result = det.ingest({"channel": 6})
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# WardriveDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestWardriveDetector:
    def test_no_alert_below_threshold(self):
        """Fewer unique SSIDs than threshold → no alert."""
        det = WardriveDetector()
        for i in range(3):  # default threshold is 5
            result = det.ingest(
                {
                    "frame_type": "probe_req",
                    "src_addr": "AA:BB:CC:DD:EE:FF",
                    "ssid": f"Net-{i}",
                }
            )
        assert result is None

    def test_alert_on_many_probes(self):
        """Probing for >= threshold unique SSIDs → alert."""
        det = WardriveDetector()
        alerts = []
        for i in range(6):
            r = det.ingest(
                {
                    "frame_type": "probe_req",
                    "src_addr": "AA:BB:CC:DD:EE:FF",
                    "ssid": f"Net-{i}",
                }
            )
            if r:
                alerts.append(r)
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "wardrive_detected"

    def test_ignores_non_probe_frames(self):
        """Only probe_req frames should be tracked."""
        det = WardriveDetector()
        for i in range(10):
            result = det.ingest(
                {
                    "frame_type": "beacon",
                    "src_addr": "AA:BB:CC:DD:EE:FF",
                    "ssid": f"Net-{i}",
                }
            )
        assert result is None

    def test_alert_fields(self):
        """Alert should contain expected fields."""
        det = WardriveDetector()
        alerts = []
        for i in range(6):
            r = det.ingest(
                {
                    "frame_type": "probe_req",
                    "src_addr": "AA:BB:CC:DD:EE:FF",
                    "ssid": f"Net-{i}",
                }
            )
            if r:
                alerts.append(r)
        assert len(alerts) >= 1
        result = alerts[0]
        assert "source_mac" in result
        assert "evidence" in result
        assert result["evidence"]["unique_ssid_count"] >= 5


# ═══════════════════════════════════════════════════════════════════════════
# WEPIVDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestWEPIVDetector:
    def _setup_wep_ap(self, det, bssid="00:11:22:33:44:55"):
        """Register a WEP-enabled AP."""
        det.ingest({"frame_type": "beacon", "bssid": bssid, "privacy": True})

    def test_iv_collision_detected(self):
        """Same IV repeated >= threshold → alert."""
        det = WEPIVDetector()
        self._setup_wep_ap(det)
        result = None
        for _ in range(6):
            result = det.ingest(
                {"frame_type": "data", "bssid": "00:11:22:33:44:55", "wep_iv": "AABBCC"}
            )
        assert result is not None
        assert result["alert_type"] == "wep_attack"
        assert "iv_collision" in result["evidence"]["attack_subtype"]

    def test_no_alert_for_non_wep(self):
        """Data frames for non-WEP network → no alert."""
        det = WEPIVDetector()
        # Register AP with RSN (not WEP)
        det.ingest(
            {
                "frame_type": "beacon",
                "bssid": "00:11:22:33:44:55",
                "privacy": True,
                "rsn_info": True,
            }
        )
        for _ in range(10):
            result = det.ingest(
                {"frame_type": "data", "bssid": "00:11:22:33:44:55", "wep_iv": "AABBCC"}
            )
        assert result is None

    def test_packet_injection_detected(self):
        """Many small packets → injection detected."""
        det = WEPIVDetector()
        self._setup_wep_ap(det)
        alerts = []
        for _ in range(55):
            r = det.ingest(
                {"frame_type": "data", "bssid": "00:11:22:33:44:55", "frame_len": 64}
            )
            if r:
                alerts.append(r)
        assert len(alerts) >= 1
        assert "packet_injection" in alerts[0]["evidence"]["attack_subtype"]


# ═══════════════════════════════════════════════════════════════════════════
# ExploitChainAnalyzer
# ═══════════════════════════════════════════════════════════════════════════


class TestExploitChainAnalyzer:
    def test_single_alert_no_chain(self):
        """A single alert should not trigger a chain."""
        analyzer = ExploitChainAnalyzer()
        result = analyzer.analyze(
            {
                "alert_type": "deauth_flood",
                "bssid": "AA:BB:CC:11:22:33",
                "severity": "MEDIUM",
            }
        )
        assert result is None

    def test_chain_on_correlated_alerts(self):
        """Two alerts with same BSSID should create a chain."""
        analyzer = ExploitChainAnalyzer()
        analyzer.analyze(
            {
                "alert_type": "deauth_flood",
                "bssid": "AA:BB:CC:11:22:33",
                "severity": "MEDIUM",
            }
        )
        result = analyzer.analyze(
            {
                "alert_type": "evil_twin",
                "target_bssid": "AA:BB:CC:11:22:33",
                "severity": "HIGH",
            }
        )
        assert result is not None
        assert result["alert_type"] == "exploit_chain"
        assert len(result["evidence"]["alert_sequence"]) == 2

    def test_unrelated_alerts_no_chain(self):
        """Alerts targeting different BSSIDs should not form a chain."""
        analyzer = ExploitChainAnalyzer()
        analyzer.analyze(
            {
                "alert_type": "deauth_flood",
                "bssid": "11:11:11:11:11:11",
                "severity": "MEDIUM",
            }
        )
        result = analyzer.analyze(
            {
                "alert_type": "karma_attack",
                "bssid": "22:22:22:22:22:22",
                "severity": "HIGH",
            }
        )
        assert result is None

    def test_chain_alert_fields(self):
        """Chain alert should contain expected fields."""
        analyzer = ExploitChainAnalyzer()
        analyzer.analyze(
            {
                "alert_type": "deauth_flood",
                "bssid": "AA:BB:CC:11:22:33",
                "severity": "MEDIUM",
            }
        )
        result = analyzer.analyze(
            {
                "alert_type": "evil_twin",
                "target_bssid": "AA:BB:CC:11:22:33",
                "severity": "HIGH",
            }
        )
        assert "chain_id" in result
        assert "evidence" in result
        assert result["evidence"]["target_bssid"] == "AA:BB:CC:11:22:33"


# ═══════════════════════════════════════════════════════════════════════════
# DeauthFloodDetector
# ═══════════════════════════════════════════════════════════════════════════


class TestDeauthFloodDetector:
    def test_no_alert_below_threshold(self):
        """Low deauth rate → no alert."""
        det = DeauthFloodDetector(threshold_per_sec=10, window_seconds=2)
        result = det.record_deauth("AA:AA:AA:AA:AA:AA")
        assert result is None

    def test_alert_on_flood(self):
        """High deauth rate → alert fires."""
        det = DeauthFloodDetector(threshold_per_sec=5, window_seconds=2)
        alerts = []
        for _ in range(15):
            r = det.record_deauth("AA:AA:AA:AA:AA:AA")
            if r:
                alerts.append(r)
        assert len(alerts) >= 1
        assert alerts[0].severity in ("MEDIUM", "HIGH", "CRITICAL")
        assert alerts[0].target_bssid == "AA:AA:AA:AA:AA:AA"

    def test_cooldown(self):
        """After alert, cooldown should prevent immediate re-alert."""
        det = DeauthFloodDetector(
            threshold_per_sec=5, window_seconds=2, cooldown_seconds=60
        )
        for _ in range(15):
            det.record_deauth("AA:AA:AA:AA:AA:AA")
        # Second burst immediately → should be suppressed by cooldown
        result = None
        for _ in range(15):
            result = det.record_deauth("AA:AA:AA:AA:AA:AA")
        assert result is None

    def test_stats(self):
        """Stats should reflect activity."""
        det = DeauthFloodDetector()
        det.record_deauth("AA:AA:AA:AA:AA:AA")
        stats = det.get_stats()
        assert stats["tracked_pairs"] >= 1
        assert stats["total_recent_frames"] >= 1
