"""
Sentinel NetLab - Alert Normalization Helper

Ensures every alert dict returned by the orchestrator has the
required fields and consistent structure.
"""

from datetime import UTC, datetime
from typing import Any

# Required fields that every normalized alert must have.
REQUIRED_FIELDS = ("alert_type", "severity", "title", "description", "sensor_id")

# Optional fields that are preserved when present.
OPTIONAL_FIELDS = (
    "bssid",
    "ssid",
    "evidence",
    "risk_score",
    "mitre_attack",
    "timestamp",
)


def normalize_alert(
    raw: dict[str, Any],
    defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Return a copy of *raw* with all required fields guaranteed present.

    Missing required fields are filled from *defaults* or set to
    sensible fallback values.  Optional fields are included only
    when they already exist in *raw*.
    """
    defaults = defaults or {}
    out: dict[str, Any] = {}

    # Required fields
    out["alert_type"] = raw.get("alert_type", defaults.get("alert_type", "unknown"))
    out["severity"] = raw.get("severity", defaults.get("severity", "MEDIUM"))
    out["title"] = raw.get("title", defaults.get("title", "Detection Alert"))
    out["description"] = raw.get("description", defaults.get("description", ""))
    out["sensor_id"] = raw.get("sensor_id", defaults.get("sensor_id", ""))

    # Timestamp — always present
    out["timestamp"] = raw.get(
        "timestamp", defaults.get("timestamp", datetime.now(UTC).isoformat())
    )

    # Optional fields — include only when present in raw or defaults
    for field in OPTIONAL_FIELDS:
        if field == "timestamp":
            continue  # already handled above
        value = raw.get(field, defaults.get(field))
        if value is not None:
            out[field] = value

    # Pass through any extra keys the adapter explicitly set
    for key, value in raw.items():
        if key not in out:
            out[key] = value

    return out
