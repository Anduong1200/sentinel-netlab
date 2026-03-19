"""
Helpers for loading wardrive session data into the TUI.

These helpers avoid importing Textual so they can be tested without optional UI
dependencies being installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_WARDRIVE_FILENAME = "wardrive_session.json"


@dataclass
class WardriveRecentSighting:
    """Compact view model for the TUI wardrive panel."""

    timestamp: str
    ssid: str
    bssid: str
    rssi_dbm: int | None
    security: str
    gps_label: str


@dataclass
class WardriveSnapshot:
    """Derived wardrive session summary for dashboard rendering."""

    source_path: Path
    status: str = "Waiting for wardrive session file."
    sensor_id: str = "—"
    unique_networks: int = 0
    total_sightings: int = 0
    gps_points: int = 0
    last_update: str = "—"
    last_fix: str = "No GPS fix"
    recent_sightings: list[WardriveRecentSighting] = field(default_factory=list)


def resolve_wardrive_session_path(
    project_root: Path,
    override: str | None = None,
) -> Path:
    """Resolve the wardrive session file path the TUI should follow."""
    if override:
        return Path(override).expanduser()
    return project_root / DEFAULT_WARDRIVE_FILENAME


def load_wardrive_snapshot(
    session_path: Path,
    limit: int = 5,
) -> WardriveSnapshot:
    """Load a wardrive session JSON file into a TUI-friendly snapshot."""
    snapshot = WardriveSnapshot(source_path=session_path)
    if not session_path.exists():
        return snapshot

    try:
        with open(session_path) as f:
            raw_data = json.load(f)
    except json.JSONDecodeError:
        snapshot.status = "Wardrive file is updating..."
        return snapshot
    except Exception as exc:
        snapshot.status = f"Wardrive read error: {exc}"
        return snapshot

    if not isinstance(raw_data, dict):
        snapshot.status = "Wardrive file format invalid."
        return snapshot

    snapshot.sensor_id = str(raw_data.get("sensor_id") or "—")
    snapshot.unique_networks = _coerce_int(raw_data.get("unique_networks"))
    snapshot.total_sightings = _coerce_int(raw_data.get("total_sightings"))

    raw_sightings = raw_data.get("sightings")
    if not isinstance(raw_sightings, list):
        snapshot.status = "Wardrive session contains no sightings list."
        return snapshot

    if not raw_sightings:
        snapshot.status = "Wardrive session is ready but empty."
        return snapshot

    snapshot.status = "Wardrive session loaded."
    snapshot.last_update = _format_time(raw_sightings[-1].get("timestamp"))

    for sighting in raw_sightings:
        if _extract_gps_label(sighting.get("gps")) != "No fix":
            snapshot.gps_points += 1

    latest_fix = next(
        (
            _extract_gps_label(item.get("gps"))
            for item in reversed(raw_sightings)
            if _extract_gps_label(item.get("gps")) != "No fix"
        ),
        "No GPS fix",
    )
    snapshot.last_fix = latest_fix

    for sighting in list(reversed(raw_sightings))[:limit]:
        if not isinstance(sighting, dict):
            continue
        snapshot.recent_sightings.append(
            WardriveRecentSighting(
                timestamp=_format_time(sighting.get("timestamp")),
                ssid=str(sighting.get("ssid") or "<hidden>"),
                bssid=str(sighting.get("bssid") or "—"),
                rssi_dbm=_coerce_optional_int(sighting.get("rssi_dbm")),
                security=str(sighting.get("security") or "UNKNOWN").upper(),
                gps_label=_extract_gps_label(sighting.get("gps")),
            )
        )

    return snapshot


def _extract_gps_label(raw_gps: Any) -> str:
    if not isinstance(raw_gps, dict):
        return "No fix"

    lat = raw_gps.get("lat")
    lon = raw_gps.get("lon")
    if lat is None or lon is None:
        return "No fix"

    try:
        return f"{float(lat):.5f}, {float(lon):.5f}"
    except (TypeError, ValueError):
        return "No fix"


def _format_time(raw_timestamp: Any) -> str:
    if not raw_timestamp:
        return "—"

    text = str(raw_timestamp).strip()
    if not text:
        return "—"

    try:
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).strftime("%H:%M:%S")
    except ValueError:
        return text[-8:] if len(text) >= 8 else text


def _coerce_int(raw_value: Any) -> int:
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return 0


def _coerce_optional_int(raw_value: Any) -> int | None:
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return None
