"""
Sentinel NetLab - Detector Profiles

Pre-defined detector sets for common operational scenarios.
The ``detector_profile`` config key selects which detectors are enabled.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Profile definitions ─────────────────────────────────────────────────────

PROFILES: dict[str, list[str]] = {
    # Default: low-latency, low-FP set for real-time deployment.
    "lite_realtime": [
        "deauth_flood",
        "disassoc_flood",
        "beacon_flood",
        "krack",
        "pmkid",
        "wep_iv",
        "rules",
    ],
    # Full WIDS: all detectors for comprehensive monitoring.
    "full_wids": [
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
    ],
    # Audit / offline replay: same as full_wids (extensible later).
    "audit_offline": [
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
    ],
}

DEFAULT_PROFILE = "lite_realtime"


def get_profile(name: str) -> list[str]:
    """
    Return the detector ID list for the given profile name.

    Falls back to ``lite_realtime`` if the name is unknown.
    """
    if name not in PROFILES:
        logger.warning(
            "Unknown detector profile '%s', falling back to '%s'",
            name,
            DEFAULT_PROFILE,
        )
        return list(PROFILES[DEFAULT_PROFILE])
    return list(PROFILES[name])


def list_profiles() -> list[str]:
    """Return the names of all available profiles."""
    return sorted(PROFILES.keys())
