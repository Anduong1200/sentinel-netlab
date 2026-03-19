#!/usr/bin/env python3
"""
Tests for the sensor-side Detection Orchestrator.

Covers: registry, profiles, adapters, normalizer, orchestrator,
config propagation, stage scheduling, prefilter, and analysis helper.
"""

import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_registry_has_all_detectors(self):
        from sensor.detection.registry import get_registry

        registry = get_registry()
        expected = {
            "deauth_flood",
            "disassoc_flood",
            "beacon_flood",
            "krack",
            "pmkid",
            "wep_iv",
            "evil_twin",
            "karma",
            "jamming",
            "wardrive",
            "rules",
        }
        assert expected == set(registry.keys())

    def test_build_detector_known_id(self):
        from sensor.detection.registry import build_detector

        det = build_detector("beacon_flood")
        assert det.detector_id == "beacon_flood"

    def test_build_detector_unknown_id_raises(self):
        from sensor.detection.registry import build_detector

        with pytest.raises(KeyError, match="Unknown detector"):
            build_detector("nonexistent_detector")

    def test_build_detector_with_config(self):
        """Config dict is accepted and stored."""
        from sensor.detection.registry import build_detector

        det = build_detector("deauth_flood", config={"threshold_per_sec": 99.0})
        assert det._det.threshold_per_sec == 99.0


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_lite_realtime_members(self):
        from sensor.detection.profiles import get_profile

        ids = get_profile("lite_realtime")
        assert "deauth_flood" in ids
        assert "disassoc_flood" in ids
        assert "beacon_flood" in ids
        assert "krack" in ids
        assert "pmkid" in ids
        assert "wep_iv" in ids
        assert "rules" in ids
        assert len(ids) == 7

    def test_full_wids_has_all(self):
        from sensor.detection.profiles import get_profile
        from sensor.detection.registry import get_registry

        ids = get_profile("full_wids")
        assert set(ids) == set(get_registry().keys())

    def test_unknown_profile_falls_back(self):
        from sensor.detection.profiles import get_profile

        ids = get_profile("nonexistent_profile")
        assert ids == get_profile("lite_realtime")

    def test_list_profiles(self):
        from sensor.detection.profiles import list_profiles

        names = list_profiles()
        assert "lite_realtime" in names
        assert "full_wids" in names
        assert "audit_offline" in names


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class TestNormalizer:
    def test_fills_required_fields(self):
        from sensor.detection.normalizer import normalize_alert

        result = normalize_alert({})
        assert result["alert_type"] == "unknown"
        assert result["severity"] == "MEDIUM"
        assert result["title"] == "Detection Alert"
        assert "sensor_id" in result
        assert "timestamp" in result

    def test_preserves_existing_fields(self):
        from sensor.detection.normalizer import normalize_alert

        raw = {
            "alert_type": "krack_attack",
            "severity": "CRITICAL",
            "title": "KRACK",
            "description": "desc",
            "sensor_id": "s-01",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "mitre_attack": "T1557.002",
        }
        result = normalize_alert(raw)
        assert result["alert_type"] == "krack_attack"
        assert result["severity"] == "CRITICAL"
        assert result["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert result["mitre_attack"] == "T1557.002"

    def test_defaults_override(self):
        from sensor.detection.normalizer import normalize_alert

        result = normalize_alert({}, defaults={"sensor_id": "s-99"})
        assert result["sensor_id"] == "s-99"


# ---------------------------------------------------------------------------
# Config Propagation (Phase 1)
# ---------------------------------------------------------------------------


class TestConfigPropagation:
    """Adapters properly pass config into underlying detectors."""

    def test_deauth_config_changes_threshold(self):
        from sensor.detection.adapters import DeauthFloodDetectorAdapter

        low = DeauthFloodDetectorAdapter(config={"threshold_per_sec": 1.0})
        high = DeauthFloodDetectorAdapter(config={"threshold_per_sec": 999.0})
        assert low._det.threshold_per_sec == 1.0
        assert high._det.threshold_per_sec == 999.0

    def test_beacon_flood_config_threshold(self):
        from sensor.detection.adapters import BeaconFloodDetectorAdapter

        adapter = BeaconFloodDetectorAdapter(config={"unique_ssid_threshold": 5})
        assert adapter._det.config.unique_ssid_threshold == 5

    def test_krack_config_m3_threshold(self):
        from sensor.detection.adapters import KRACKDetectorAdapter

        adapter = KRACKDetectorAdapter(config={"m3_retransmit_threshold": 10})
        assert adapter._det.config.m3_retransmit_threshold == 10

    def test_pmkid_config_threshold(self):
        from sensor.detection.adapters import PMKIDDetectorAdapter

        adapter = PMKIDDetectorAdapter(config={"eapol_m1_threshold": 5})
        assert adapter._det.config.eapol_m1_threshold == 5

    def test_wardrive_config_threshold(self):
        from sensor.detection.adapters import WardriveDetectorAdapter

        adapter = WardriveDetectorAdapter(config={"unique_ssid_threshold": 2})
        assert adapter._det.config.unique_ssid_threshold == 2

    def test_karma_config_threshold(self):
        from sensor.detection.adapters import KarmaDetectorAdapter

        adapter = KarmaDetectorAdapter(config={"ssid_threshold": 2})
        assert adapter._det.config.ssid_threshold == 2

    def test_wep_iv_config_threshold(self):
        from sensor.detection.adapters import WEPIVDetectorAdapter

        adapter = WEPIVDetectorAdapter(config={"iv_collision_threshold": 2})
        assert adapter._det.config.iv_collision_threshold == 2

    def test_rule_engine_accepts_config_without_crash(self):
        """RuleEngine has no config; adapter must not crash."""
        from sensor.detection.adapters import RuleEngineAdapter

        adapter = RuleEngineAdapter(config={"some_key": 42})
        assert adapter._det is not None

    def test_unknown_config_keys_ignored(self):
        """Unknown keys should not crash adapter construction."""
        from sensor.detection.adapters import BeaconFloodDetectorAdapter

        adapter = BeaconFloodDetectorAdapter(
            config={"nonexistent_key": 999, "unique_ssid_threshold": 3}
        )
        assert adapter._det.config.unique_ssid_threshold == 3


# ---------------------------------------------------------------------------
# Prefilter / Routing Metadata (Phase 3)
# ---------------------------------------------------------------------------


class TestPrefilter:
    """Adapter routing metadata and accepts() prefilter."""

    def test_deauth_adapter_accepts_deauth(self):
        from sensor.detection.adapters import DeauthFloodDetectorAdapter

        adapter = DeauthFloodDetectorAdapter()
        assert adapter.accepts({"frame_type": "deauth", "frame_subtype": 12})

    def test_deauth_adapter_rejects_beacon(self):
        from sensor.detection.adapters import DeauthFloodDetectorAdapter

        adapter = DeauthFloodDetectorAdapter()
        assert not adapter.accepts({"frame_type": "beacon", "frame_subtype": 8})

    def test_beacon_adapter_rejects_deauth(self):
        from sensor.detection.adapters import BeaconFloodDetectorAdapter

        adapter = BeaconFloodDetectorAdapter()
        assert not adapter.accepts({"frame_type": "deauth"})

    def test_wardrive_adapter_accepts_probe_req(self):
        from sensor.detection.adapters import WardriveDetectorAdapter

        adapter = WardriveDetectorAdapter()
        assert adapter.accepts({"frame_type": "probe_req"})

    def test_wardrive_adapter_rejects_beacon(self):
        from sensor.detection.adapters import WardriveDetectorAdapter

        adapter = WardriveDetectorAdapter()
        assert not adapter.accepts({"frame_type": "beacon"})

    def test_jamming_accepts_any(self):
        """Jamming detector has broad metadata — accepts anything."""
        from sensor.detection.adapters import JammingDetectorAdapter

        adapter = JammingDetectorAdapter()
        assert adapter.accepts({"frame_type": "beacon"})
        assert adapter.accepts({"frame_type": "data"})

    def test_rules_accepts_any(self):
        from sensor.detection.adapters import RuleEngineAdapter

        adapter = RuleEngineAdapter()
        assert adapter.accepts({"frame_type": "anything"})

    def test_evil_twin_requires_bssid_ssid(self):
        from sensor.detection.adapters import EvilTwinDetectorAdapter

        adapter = EvilTwinDetectorAdapter()
        assert adapter.accepts({"frame_type": "beacon", "bssid": "AA", "ssid": "X"})
        # Missing ssid
        assert not adapter.accepts({"frame_type": "beacon", "bssid": "AA"})


# ---------------------------------------------------------------------------
# Stage Scheduling (Phase 2)
# ---------------------------------------------------------------------------


class TestStageScheduling:
    def test_config_driven_stage_override(self):
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors.enabled = ["deauth_flood", "rules"]
        config.detectors.default_profile = "lite_realtime"
        config.detectors.thresholds = {}
        config.detectors.fast_path = ["rules"]
        config.detectors.stateful_path = []
        config.detectors.correlation_path = ["deauth_flood"]
        config.detectors.profiles = {}

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")

        fast_ids = [did for did, _ in orch._stages["fast_path"]]
        corr_ids = [did for did, _ in orch._stages["correlation_path"]]
        assert "rules" in fast_ids
        assert "deauth_flood" in corr_ids

    def test_config_defined_custom_profile(self):
        """Config-defined profile takes precedence over built-in."""
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors.enabled = []
        config.detectors.default_profile = "my_custom"
        config.detectors.thresholds = {}
        config.detectors.fast_path = []
        config.detectors.stateful_path = []
        config.detectors.correlation_path = []
        config.detectors.profiles = {"my_custom": ["beacon_flood", "rules"]}

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")

        loaded = []
        for stage_list in orch._stages.values():
            for det_id, _ in stage_list:
                loaded.append(det_id)

        assert set(loaded) == {"beacon_flood", "rules"}

    def test_unknown_detector_id_in_enabled_warned_and_skipped(self):
        """Unknown detector IDs should be skipped with a warning."""
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors.enabled = ["beacon_flood", "NONEXISTENT"]
        config.detectors.default_profile = "lite_realtime"
        config.detectors.thresholds = {}
        config.detectors.fast_path = []
        config.detectors.stateful_path = []
        config.detectors.correlation_path = []
        config.detectors.profiles = {}

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")

        loaded = []
        for stage_list in orch._stages.values():
            for det_id, _ in stage_list:
                loaded.append(det_id)

        assert "beacon_flood" in loaded
        assert "NONEXISTENT" not in loaded

    def test_profile_precedence_enabled_over_profile(self):
        """Explicit enabled list > config-defined profile > built-in profile."""
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors.enabled = ["rules"]
        config.detectors.default_profile = "full_wids"
        config.detectors.thresholds = {}
        config.detectors.fast_path = []
        config.detectors.stateful_path = []
        config.detectors.correlation_path = []
        config.detectors.profiles = {"full_wids": ["beacon_flood", "karma"]}

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")

        loaded = []
        for stage_list in orch._stages.values():
            for det_id, _ in stage_list:
                loaded.append(det_id)

        assert loaded == ["rules"]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class TestOrchestrator:
    def test_from_config_default_profile(self):
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors = None

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")

        loaded = []
        for stage_list in orch._stages.values():
            for det_id, _ in stage_list:
                loaded.append(det_id)

        assert set(loaded) == {
            "deauth_flood",
            "disassoc_flood",
            "beacon_flood",
            "krack",
            "pmkid",
            "wep_iv",
            "rules",
        }

    def test_process_returns_list(self):
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        config = MagicMock()
        config.detectors = None

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-test")
        result = orch.process(
            {"frame_type": "beacon", "bssid": "AA:BB:CC:11:22:33"},
            context={"sensor_id": "s-test"},
        )
        assert isinstance(result, list)

    def test_prefilter_skips_mismatched_detectors(self):
        """Orchestrator should use accepts() to skip obviously irrelevant detectors."""
        from sensor.detection.interface import BaseSensorDetector
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        class NarrowDetector(BaseSensorDetector):
            detector_id = "narrow"
            supported_event_types = {"magic_frame"}
            call_count = 0

            def process(self, telemetry, context=None):
                NarrowDetector.call_count += 1
                return []

        NarrowDetector.call_count = 0
        det = NarrowDetector()
        orch = SensorDetectionOrchestrator(
            detectors={"narrow": det}, sensor_id="s-test"
        )
        orch.process({"frame_type": "beacon"})
        assert NarrowDetector.call_count == 0, (
            "Detector should have been skipped by prefilter"
        )

    def test_alert_normalization_on_output(self):
        from sensor.detection.interface import BaseSensorDetector
        from sensor.detection.orchestrator import SensorDetectionOrchestrator

        class AlertDetector(BaseSensorDetector):
            detector_id = "alert_gen"

            def process(self, telemetry, context=None):
                return [
                    {
                        "alert_type": "test",
                        "severity": "HIGH",
                        "title": "T",
                        "description": "D",
                    }
                ]

        orch = SensorDetectionOrchestrator(
            detectors={"alert_gen": AlertDetector()}, sensor_id="s-norm"
        )
        alerts = orch.process({})
        assert len(alerts) == 1
        assert alerts[0]["sensor_id"] == "s-norm"
        assert "timestamp" in alerts[0]


# ---------------------------------------------------------------------------
# Config Persistence (Phase 5)
# ---------------------------------------------------------------------------


class TestConfigPersistence:
    def test_to_dict_includes_detectors(self):
        from sensor.config import ConfigManager

        mgr = ConfigManager.__new__(ConfigManager)
        from sensor.config import Config

        mgr.config = Config()
        mgr.config.detectors.default_profile = "full_wids"
        result = mgr.to_dict()
        assert "detectors" in result
        assert result["detectors"]["default_profile"] == "full_wids"

    def test_save_load_roundtrip(self, tmp_path):
        import json

        from sensor.config import Config, ConfigManager

        mgr = ConfigManager.__new__(ConfigManager)
        mgr.config = Config()
        mgr.config.detectors.default_profile = "audit_offline"
        mgr.config_path = tmp_path / "test.json"

        mgr.save_config()

        with open(tmp_path / "test.json") as f:
            data = json.load(f)

        assert data["detectors"]["default_profile"] == "audit_offline"


# ---------------------------------------------------------------------------
# Analysis Orchestrator (Phase 4)
# ---------------------------------------------------------------------------


class TestAnalysisOrchestrator:
    def test_correlate_alert_returns_chain(self):
        from sensor.detection.analysis_orchestrator import SensorAnalysisOrchestrator

        chain_analyzer = MagicMock()
        chain_analyzer.analyze.return_value = {
            "alert_type": "exploit_chain",
            "title": "Deauth -> Evil Twin",
        }

        analysis = SensorAnalysisOrchestrator(
            risk_engine=MagicMock(),
            baseline=MagicMock(),
            chain_analyzer=chain_analyzer,
            sensor_id="s-01",
        )
        result = analysis.correlate_alert({"alert_type": "deauth_flood"})
        assert result is not None
        assert result["sensor_id"] == "s-01"

    def test_correlate_alert_returns_none(self):
        from sensor.detection.analysis_orchestrator import SensorAnalysisOrchestrator

        chain_analyzer = MagicMock()
        chain_analyzer.analyze.return_value = None

        analysis = SensorAnalysisOrchestrator(
            risk_engine=MagicMock(),
            baseline=MagicMock(),
            chain_analyzer=chain_analyzer,
            sensor_id="s-01",
        )
        result = analysis.correlate_alert({"alert_type": "test"})
        assert result is None

    def test_analyze_telemetry_only_on_10th_frame(self):
        from sensor.detection.analysis_orchestrator import SensorAnalysisOrchestrator

        analysis = SensorAnalysisOrchestrator(
            risk_engine=MagicMock(),
            baseline=MagicMock(),
            chain_analyzer=MagicMock(),
            sensor_id="s-01",
        )
        # Not a multiple of 10
        assert analysis.analyze_telemetry({}, frame_count=3) == []

    def test_analyze_telemetry_skips_during_learning(self):
        from sensor.detection.analysis_orchestrator import SensorAnalysisOrchestrator

        baseline = MagicMock()
        baseline.learning_mode = True
        baseline.check_deviation.return_value = None

        analysis = SensorAnalysisOrchestrator(
            risk_engine=MagicMock(),
            baseline=baseline,
            chain_analyzer=MagicMock(),
            sensor_id="s-01",
        )
        assert analysis.analyze_telemetry({}, frame_count=10) == []
