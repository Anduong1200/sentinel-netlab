"""
Sentinel NetLab - Detector Adapters

Thin wrappers around existing algos/*.py detectors.  Each adapter
implements BaseSensorDetector.process() and converts the native
return value into a list of normalized alert dicts.

Config propagation:
    Every adapter maps ``self.config`` (a plain dict from
    ``DetectorsConfig.thresholds[detector_id]``) into the actual constructor
    accepted by the underlying detector.  Helper ``_build_dataclass_config``
    filters keys to only those the target dataclass recognises.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, fields as dc_fields
from typing import Any

from sensor.detection.interface import BaseSensorDetector
from sensor.detection.normalizer import normalize_alert

logger = logging.getLogger(__name__)


# ── helpers ──────────────────────────────────────────────────────────────

def _build_dataclass_config(dc_class: type, overrides: dict[str, Any]):
    """
    Build a dataclass instance from *overrides*, silently ignoring keys
    that the dataclass does not define.
    """
    valid_keys = {f.name for f in dc_fields(dc_class)}
    filtered = {k: v for k, v in overrides.items() if k in valid_keys}
    return dc_class(**filtered)


# ---------------------------------------------------------------------------
# fast_path adapters
# ---------------------------------------------------------------------------


class DeauthFloodDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.dos.DeauthFloodDetector.record_deauth()``."""

    detector_id = "deauth_flood"
    supported_event_types = {"deauth"}
    supported_frame_subtypes = {12}

    # DeauthFloodDetector accepts explicit kwargs, not a config dataclass.
    _SUPPORTED_KEYS = {"threshold_per_sec", "window_seconds", "cooldown_seconds", "state_file"}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.dos import DeauthFloodDetector

        kwargs = {k: v for k, v in self.config.items() if k in self._SUPPORTED_KEYS}
        self._det = DeauthFloodDetector(**kwargs)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ctx = context or {}
        result = self._det.record_deauth(
            bssid=telemetry.get("bssid", ""),
            client_mac=telemetry.get("mac_dst", "ff:ff:ff:ff:ff:ff"),
            sensor_id=ctx.get("sensor_id", ""),
        )
        if result is None:
            return []

        raw = {
            "alert_type": "deauth_flood",
            "severity": result.severity,
            "title": f"Deauth Flood: {result.target_bssid}",
            "description": f"Deauth flood: {result.rate_per_sec:.1f} f/s",
            "bssid": result.target_bssid,
            "evidence": result.evidence,
            "mitre_attack": result.mitre_attack,
        }
        return [normalize_alert(raw, {"sensor_id": ctx.get("sensor_id", "")})]


class DisassocFloodDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.disassoc_detector.DisassocFloodDetector.ingest()``."""

    detector_id = "disassoc_flood"
    supported_event_types = {"disassoc", "disassociation"}
    supported_frame_subtypes = {10}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.disassoc_detector import DisassocConfig, DisassocFloodDetector

        cfg = _build_dataclass_config(DisassocConfig, self.config) if self.config else None
        self._det = DisassocFloodDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class BeaconFloodDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.beacon_flood_detector.BeaconFloodDetector.ingest()``."""

    detector_id = "beacon_flood"
    supported_event_types = {"beacon"}
    supported_frame_subtypes = {8}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.beacon_flood_detector import BeaconFloodConfig, BeaconFloodDetector

        cfg = _build_dataclass_config(BeaconFloodConfig, self.config) if self.config else None
        self._det = BeaconFloodDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class KRACKDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.krack_detector.KRACKDetector.ingest()``."""

    detector_id = "krack"
    supported_event_types = {"eapol", "key"}
    supported_frame_subtypes = None  # EAPOL is not a subtype; be conservative

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.krack_detector import KRACKConfig, KRACKDetector

        cfg = _build_dataclass_config(KRACKConfig, self.config) if self.config else None
        self._det = KRACKDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class PMKIDDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.pmkid_detector.PMKIDAttackDetector.ingest()``."""

    detector_id = "pmkid"
    supported_event_types = {"eapol", "auth", "authentication"}
    supported_frame_subtypes = None  # conservative: auth+eapol don't share one subtype

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.pmkid_detector import PMKIDAttackDetector, PMKIDConfig

        cfg = _build_dataclass_config(PMKIDConfig, self.config) if self.config else None
        self._det = PMKIDAttackDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class WEPIVDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.wep_iv_detector.WEPIVDetector.ingest()``."""

    detector_id = "wep_iv"
    supported_event_types = {"data"}
    required_fields = {"wep_iv"}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.wep_iv_detector import WEPConfig, WEPIVDetector

        cfg = _build_dataclass_config(WEPConfig, self.config) if self.config else None
        self._det = WEPIVDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


# ---------------------------------------------------------------------------
# stateful_path adapters
# ---------------------------------------------------------------------------


class EvilTwinDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.evil_twin.AdvancedEvilTwinDetector.ingest()``."""

    detector_id = "evil_twin"
    supported_event_types = {"beacon", "probe_resp"}
    required_fields = {"bssid", "ssid"}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.evil_twin import AdvancedEvilTwinDetector, EvilTwinConfig

        cfg = _build_dataclass_config(EvilTwinConfig, self.config) if self.config else None
        self._det = AdvancedEvilTwinDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        alerts = self._det.ingest(telemetry)
        if not alerts:
            return []

        ctx = context or {}
        sensor_id = ctx.get("sensor_id", "")
        normalized: list[dict[str, Any]] = []

        for alert in alerts:
            raw = {
                "alert_type": "evil_twin",
                "severity": alert.severity,
                "title": f"Evil Twin Detected: {alert.ssid}",
                "description": alert.recommendation,
                "evidence": (
                    alert.evidence
                    if isinstance(alert.evidence, dict)
                    else asdict(alert.evidence)
                    if hasattr(alert.evidence, "__dataclass_fields__")
                    else alert.evidence
                ),
                "risk_score": alert.score,
                "mitre_attack": alert.mitre_technique,
            }
            normalized.append(normalize_alert(raw, {"sensor_id": sensor_id}))

        return normalized


class KarmaDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.karma_detector.KarmaDetector.ingest()``."""

    detector_id = "karma"
    supported_event_types = {"beacon", "probe_resp"}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.karma_detector import KarmaConfig, KarmaDetector

        cfg = _build_dataclass_config(KarmaConfig, self.config) if self.config else None
        self._det = KarmaDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class JammingDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.jamming_detector.JammingDetector.ingest()``."""

    detector_id = "jamming"
    # Jamming inspects any frame; keep routing broad.
    supported_event_types = None

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.jamming_detector import JammingConfig, JammingDetector

        cfg = _build_dataclass_config(JammingConfig, self.config) if self.config else None
        self._det = JammingDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


class WardriveDetectorAdapter(BaseSensorDetector):
    """Wraps ``algos.wardrive_detector.WardriveDetector.ingest()``."""

    detector_id = "wardrive"
    supported_event_types = {"probe_req"}

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from algos.wardrive_detector import WardriveConfig, WardriveDetector

        cfg = _build_dataclass_config(WardriveConfig, self.config) if self.config else None
        self._det = WardriveDetector(config=cfg)

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]


# ---------------------------------------------------------------------------
# correlation_path adapters
# ---------------------------------------------------------------------------


class RuleEngineAdapter(BaseSensorDetector):
    """Wraps ``sensor.rule_engine.RuleEngine.evaluate()``.

    RuleEngine has no configurable constructor; config is a no-op but
    accepted without error for uniformity.
    """

    detector_id = "rules"
    # Rules may inspect any frame; keep routing broad.
    supported_event_types = None

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from sensor.rule_engine import RuleEngine

        self._det = RuleEngine()

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ctx = context or {}
        sensor_id = ctx.get("sensor_id", "")
        rule_alerts = self._det.evaluate(telemetry, sensor_id=sensor_id)
        if not rule_alerts:
            return []

        normalized: list[dict[str, Any]] = []
        for alert in rule_alerts:
            raw = alert.to_dict()
            raw.setdefault("alert_type", raw.get("rule_id", "rule_alert"))
            raw.setdefault("title", raw.get("rule_name", "Rule Alert"))
            normalized.append(normalize_alert(raw, {"sensor_id": sensor_id}))

        return normalized
