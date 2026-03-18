"""
Sentinel NetLab - Sensor Detection Orchestrator

Loads detectors from config / profile, schedules them by stage,
and returns a flat list of normalized alert dicts.

Stage scheduling priority:
    1. Config-driven stage lists (if non-empty)
    2. Built-in DEFAULT_STAGE_MAP
    3. Unrecognised detector IDs → correlation_path (fallback)
"""

from __future__ import annotations

import logging
from typing import Any

from sensor.detection.interface import BaseSensorDetector
from sensor.detection.normalizer import normalize_alert
from sensor.detection.profiles import DEFAULT_PROFILE, get_profile
from sensor.detection.registry import build_detector, get_registry

logger = logging.getLogger(__name__)

# ── Built-in default stage mapping ──────────────────────────────────────

DEFAULT_STAGE_MAP: dict[str, list[str]] = {
    "fast_path": [
        "deauth_flood",
        "disassoc_flood",
        "beacon_flood",
        "krack",
        "pmkid",
        "wep_iv",
    ],
    "stateful_path": [
        "evil_twin",
        "karma",
        "jamming",
        "wardrive",
    ],
    "correlation_path": [
        "rules",
    ],
}

STAGE_ORDER = ("fast_path", "stateful_path", "correlation_path")


# ── Validation helpers ──────────────────────────────────────────────────

def _validate_detector_ids(
    ids: list[str],
    label: str,
    registry: dict[str, type],
) -> list[str]:
    """Return *ids* with unknown entries removed (warned) and duplicates removed."""
    seen: set[str] = set()
    clean: list[str] = []
    for did in ids:
        if did in seen:
            logger.warning("Duplicate detector '%s' in %s — skipping", did, label)
            continue
        seen.add(did)
        if did not in registry:
            logger.warning("Unknown detector '%s' in %s — skipping", did, label)
            continue
        clean.append(did)
    return clean


def _build_stage_map(
    det_cfg: Any,
    registry: dict[str, type],
    enabled_ids: list[str],
) -> dict[str, list[str]]:
    """
    Build final stage mapping.

    Priority:
        1. ``det_cfg.fast_path / stateful_path / correlation_path`` (if non-empty)
        2. ``DEFAULT_STAGE_MAP``
        3. Any enabled detector not assigned to a stage → ``correlation_path``
    """
    stage_map: dict[str, list[str]] = {s: [] for s in STAGE_ORDER}

    config_stages_found = False
    if det_cfg is not None:
        for stage in STAGE_ORDER:
            cfg_list = getattr(det_cfg, stage, None) or []
            if cfg_list:
                config_stages_found = True
                stage_map[stage] = _validate_detector_ids(cfg_list, stage, registry)

    if not config_stages_found:
        # Fall back to built-in defaults.
        for stage in STAGE_ORDER:
            stage_map[stage] = list(DEFAULT_STAGE_MAP.get(stage, []))

    # Ensure every enabled detector appears in exactly one stage.
    assigned = set()
    for ids in stage_map.values():
        assigned.update(ids)

    for det_id in enabled_ids:
        if det_id not in assigned:
            logger.info("Auto-placing unassigned detector '%s' into correlation_path", det_id)
            stage_map["correlation_path"].append(det_id)

    return stage_map


class SensorDetectionOrchestrator:
    """
    Unified detection orchestrator for the sensor side.

    Usage::

        orch = SensorDetectionOrchestrator.from_config(config, sensor_id="s-01")
        alerts = orch.process(net_dict, context={"sensor_id": "s-01"})
        for alert in alerts:
            handle_alert(alert)
    """

    def __init__(
        self,
        detectors: dict[str, BaseSensorDetector],
        sensor_id: str = "",
        stage_map: dict[str, list[str]] | None = None,
    ):
        self.sensor_id = sensor_id

        # Resolve stage_map (may be None for tests / backward compat).
        if stage_map is None:
            stage_map = dict(DEFAULT_STAGE_MAP)

        # Organise detectors by stage for ordered execution.
        self._stages: dict[str, list[tuple[str, BaseSensorDetector]]] = {
            s: [] for s in STAGE_ORDER
        }
        assigned: set[str] = set()
        for stage in STAGE_ORDER:
            for det_id in stage_map.get(stage, []):
                if det_id in detectors:
                    self._stages[stage].append((det_id, detectors[det_id]))
                    assigned.add(det_id)

        # Place any remaining detector not in stage_map into correlation_path.
        for det_id, det in detectors.items():
            if det_id not in assigned:
                self._stages["correlation_path"].append((det_id, det))

        loaded_ids = sorted(detectors.keys())
        logger.info(
            "Detection orchestrator initialised with %d detectors: %s",
            len(detectors),
            loaded_ids,
        )

    # ── Factory ──────────────────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        config: Any,
        sensor_id: str = "",
    ) -> SensorDetectionOrchestrator:
        """
        Build an orchestrator from a ``Config`` object.

        Profile resolution precedence:
            1. ``config.detectors.enabled`` (explicit list)
            2. ``config.detectors.profiles[default_profile]`` (config-defined profile)
            3. Built-in profile from ``sensor.detection.profiles``
        """
        det_cfg = getattr(config, "detectors", None)

        enabled_ids: list[str] = []
        if det_cfg is not None:
            if det_cfg.enabled:
                enabled_ids = list(det_cfg.enabled)
            else:
                profile_name = det_cfg.default_profile or DEFAULT_PROFILE
                # Check config-defined profiles first.
                cfg_profiles = getattr(det_cfg, "profiles", None) or {}
                if profile_name in cfg_profiles and cfg_profiles[profile_name]:
                    enabled_ids = list(cfg_profiles[profile_name])
                    logger.info("Using config-defined profile '%s'", profile_name)
                else:
                    enabled_ids = get_profile(profile_name)
        else:
            enabled_ids = get_profile(DEFAULT_PROFILE)

        registry = get_registry()
        enabled_ids = _validate_detector_ids(enabled_ids, "enabled", registry)

        if not enabled_ids:
            logger.warning("No valid detectors enabled; falling back to default profile")
            enabled_ids = get_profile(DEFAULT_PROFILE)

        # Per-detector threshold overrides.
        thresholds: dict[str, dict[str, Any]] = {}
        if det_cfg is not None and hasattr(det_cfg, "thresholds"):
            thresholds = det_cfg.thresholds or {}

        # Build detector instances.
        detectors: dict[str, BaseSensorDetector] = {}
        for det_id in enabled_ids:
            if det_id not in registry:
                continue
            try:
                det_config = thresholds.get(det_id)
                detectors[det_id] = build_detector(det_id, config=det_config)
            except Exception:
                logger.exception("Failed to build detector '%s'", det_id)

        # Build stage map.
        stage_map = _build_stage_map(det_cfg, registry, list(detectors.keys()))

        return cls(detectors=detectors, sensor_id=sensor_id, stage_map=stage_map)

    # ── Runtime ──────────────────────────────────────────────────────────

    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Run enabled detectors against *telemetry* and return a flat list
        of normalized alert dicts.

        Execution follows the stage order:
        ``fast_path → stateful_path → correlation_path``.

        Uses ``detector.accepts(telemetry)`` to skip obviously irrelevant
        detectors (cheap prefilter).
        """
        ctx = context or {}
        ctx.setdefault("sensor_id", self.sensor_id)
        all_alerts: list[dict[str, Any]] = []

        for stage_name in STAGE_ORDER:
            for det_id, detector in self._stages[stage_name]:
                try:
                    # Cheap prefilter using routing metadata.
                    if not detector.accepts(telemetry):
                        continue

                    alerts = detector.process(telemetry, context=ctx)
                    for alert in alerts:
                        all_alerts.append(
                            normalize_alert(alert, {"sensor_id": ctx.get("sensor_id", "")})
                        )
                except Exception:
                    logger.exception(
                        "Detector '%s' raised during process()", det_id
                    )

        return all_alerts
