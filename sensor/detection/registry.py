"""
Sentinel NetLab - Detector Registry

Maps stable detector IDs to their adapter classes.
Adding a new detector requires only a new adapter class
and one entry here — no edits to sensor_controller.py.
"""

from __future__ import annotations

import logging
from typing import Any

from sensor.detection.interface import BaseSensorDetector

logger = logging.getLogger(__name__)

# Registry populated at import time.
# Keys are the stable detector IDs used in config and profiles.
DETECTOR_REGISTRY: dict[str, type[BaseSensorDetector]] = {}


def _populate_registry() -> None:
    """Lazy-import adapters and register them."""
    from sensor.detection.adapters import (
        BeaconFloodDetectorAdapter,
        DeauthFloodDetectorAdapter,
        DisassocFloodDetectorAdapter,
        EvilTwinDetectorAdapter,
        JammingDetectorAdapter,
        KarmaDetectorAdapter,
        KRACKDetectorAdapter,
        PMKIDDetectorAdapter,
        RuleEngineAdapter,
        WardriveDetectorAdapter,
        WEPIVDetectorAdapter,
    )

    DETECTOR_REGISTRY.update(
        {
            "deauth_flood": DeauthFloodDetectorAdapter,
            "disassoc_flood": DisassocFloodDetectorAdapter,
            "beacon_flood": BeaconFloodDetectorAdapter,
            "krack": KRACKDetectorAdapter,
            "pmkid": PMKIDDetectorAdapter,
            "wep_iv": WEPIVDetectorAdapter,
            "evil_twin": EvilTwinDetectorAdapter,
            "karma": KarmaDetectorAdapter,
            "jamming": JammingDetectorAdapter,
            "wardrive": WardriveDetectorAdapter,
            "rules": RuleEngineAdapter,
        }
    )


def get_registry() -> dict[str, type[BaseSensorDetector]]:
    """Return the detector registry, populating it on first call."""
    if not DETECTOR_REGISTRY:
        _populate_registry()
    return DETECTOR_REGISTRY


def build_detector(
    detector_id: str,
    config: dict[str, Any] | None = None,
) -> BaseSensorDetector:
    """
    Instantiate a detector adapter by its stable ID.

    Args:
        detector_id: Registered detector name (e.g. ``"deauth_flood"``).
        config: Optional per-detector configuration dict.

    Raises:
        KeyError: If *detector_id* is not in the registry.
    """
    registry = get_registry()
    if detector_id not in registry:
        raise KeyError(
            f"Unknown detector '{detector_id}'. Available: {sorted(registry.keys())}"
        )
    cls = registry[detector_id]
    return cls(config=config)
