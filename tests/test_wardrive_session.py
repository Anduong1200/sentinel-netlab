import json
from pathlib import Path

from sensor.wardrive import WardriveSession, WardriveSighting


def test_wardrive_session_save_writes_atomic_json(tmp_path: Path):
    output_path = tmp_path / "wardrive_session.json"
    session = WardriveSession(sensor_id="walker-01", output_path=output_path)
    session.add_sighting(
        WardriveSighting(
            timestamp="2026-03-19T10:00:00+00:00",
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="CafeWiFi",
            rssi_dbm=-48,
            channel=6,
            security="WPA2",
            gps={"lat": 21.0285, "lon": 105.8542},
            sensor_id="walker-01",
        )
    )

    session.save()

    data = json.loads(output_path.read_text())
    assert data["sensor_id"] == "walker-01"
    assert data["unique_networks"] == 1
    assert data["total_sightings"] == 1
    assert data["sightings"][0]["ssid"] == "CafeWiFi"
    assert not (tmp_path / "wardrive_session.json.tmp").exists()
