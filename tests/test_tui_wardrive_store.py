import json
from pathlib import Path

from sensor.tui.wardrive_store import (
    DEFAULT_WARDRIVE_FILENAME,
    load_wardrive_snapshot,
    resolve_wardrive_session_path,
)


def test_resolve_wardrive_session_path_uses_override(tmp_path: Path):
    override = tmp_path / "custom-session.json"

    resolved = resolve_wardrive_session_path(tmp_path, str(override))

    assert resolved == override


def test_resolve_wardrive_session_path_defaults_to_project_root(tmp_path: Path):
    resolved = resolve_wardrive_session_path(tmp_path)

    assert resolved == tmp_path / DEFAULT_WARDRIVE_FILENAME


def test_load_wardrive_snapshot_handles_missing_file(tmp_path: Path):
    snapshot = load_wardrive_snapshot(tmp_path / "missing.json")

    assert snapshot.status == "Waiting for wardrive session file."
    assert snapshot.total_sightings == 0
    assert snapshot.recent_sightings == []


def test_load_wardrive_snapshot_parses_recent_sightings(tmp_path: Path):
    session_path = tmp_path / "wardrive_session.json"
    session_path.write_text(
        json.dumps(
            {
                "sensor_id": "walker-01",
                "unique_networks": 2,
                "total_sightings": 3,
                "sightings": [
                    {
                        "timestamp": "2026-03-19T10:00:00+00:00",
                        "bssid": "AA:BB:CC:00:00:01",
                        "ssid": "CafeWiFi",
                        "rssi_dbm": -50,
                        "channel": 1,
                        "security": "WPA2",
                        "gps": {"lat": 21.0285, "lon": 105.8542},
                        "sensor_id": "walker-01",
                    },
                    {
                        "timestamp": "2026-03-19T10:00:05+00:00",
                        "bssid": "AA:BB:CC:00:00:02",
                        "ssid": None,
                        "rssi_dbm": -74,
                        "channel": 6,
                        "security": "Open",
                        "gps": None,
                        "sensor_id": "walker-01",
                    },
                    {
                        "timestamp": "2026-03-19T10:00:09+00:00",
                        "bssid": "AA:BB:CC:00:00:03",
                        "ssid": "OfficeNet",
                        "rssi_dbm": -44,
                        "channel": 11,
                        "security": "WPA3",
                        "gps": {"lat": 21.0291, "lon": 105.8551},
                        "sensor_id": "walker-01",
                    },
                ],
            }
        )
    )

    snapshot = load_wardrive_snapshot(session_path, limit=2)

    assert snapshot.status == "Wardrive session loaded."
    assert snapshot.sensor_id == "walker-01"
    assert snapshot.unique_networks == 2
    assert snapshot.total_sightings == 3
    assert snapshot.gps_points == 2
    assert snapshot.last_update == "10:00:09"
    assert snapshot.last_fix == "21.02910, 105.85510"
    assert len(snapshot.recent_sightings) == 2
    assert snapshot.recent_sightings[0].ssid == "OfficeNet"
    assert snapshot.recent_sightings[1].ssid == "<hidden>"


def test_load_wardrive_snapshot_handles_invalid_json(tmp_path: Path):
    session_path = tmp_path / "wardrive_session.json"
    session_path.write_text("{not-json")

    snapshot = load_wardrive_snapshot(session_path)

    assert snapshot.status == "Wardrive file is updating..."
