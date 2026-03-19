from pathlib import Path

import yaml

from sensor.tui.config_store import (
    coerce_sensor_id,
    load_saved_tui_settings,
    parse_geo_coordinate,
    persist_tui_settings,
    resolve_config_path,
    validate_tui_settings,
)


def test_resolve_prefers_real_config(tmp_path: Path):
    (tmp_path / "config.example.yaml").write_text("mock_mode: true\n")
    (tmp_path / "config.yaml").write_text("mock_mode: false\n")

    resolved = resolve_config_path(tmp_path)

    assert resolved == tmp_path / "config.yaml"


def test_persist_tui_settings_creates_project_config(tmp_path: Path):
    example = tmp_path / "config.example.yaml"
    example.write_text("sensor:\n  id: demo\n")

    target = persist_tui_settings(
        project_root=tmp_path,
        current_config_path=example,
        settings={
            "mode": "pcap",
            "sensor_id": "lab-01",
            "interface": "wlan1mon",
            "pcap_path": "/tmp/sample.pcap",
            "ml_enabled": True,
            "geo_enabled": False,
            "anonymize": True,
        },
    )

    assert target == tmp_path / "config.yaml"
    data = yaml.safe_load(target.read_text())
    assert data["sensor"]["id"] == "lab-01"
    assert data["capture"]["interface"] == "wlan1mon"
    assert data["capture"]["pcap_file"] == "/tmp/sample.pcap"
    assert data["mock_mode"] is False
    assert data["ml"]["enabled"] is True
    assert data["privacy"]["anonymize_ssid"] is True


def test_load_saved_tui_settings_round_trip(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    persist_tui_settings(
        project_root=tmp_path,
        current_config_path=config_path,
        settings={
            "mode": "mock",
            "sensor_id": "lab-02",
            "interface": "wlan9mon",
            "pcap_path": "",
            "ml_enabled": False,
            "geo_enabled": True,
            "geo_sensor_x_m": "12.5",
            "geo_sensor_y_m": "4.0",
            "anonymize": False,
        },
    )

    settings = load_saved_tui_settings(config_path)

    assert settings["mode"] == "mock"
    assert settings["sensor_id"] == "lab-02"
    assert settings["interface"] == "wlan9mon"
    assert settings["geo_enabled"] is True
    assert settings["geo_sensor_x_m"] == "12.5"
    assert settings["geo_sensor_y_m"] == "4.0"
    assert settings["anonymize"] is False


def test_coerce_sensor_id_uses_fallback_for_blank_values():
    assert coerce_sensor_id("", "sensor-fallback") == "sensor-fallback"
    assert coerce_sensor_id("  ", "sensor-fallback") == "sensor-fallback"
    assert coerce_sensor_id("sensor-live", "sensor-fallback") == "sensor-live"


def test_parse_geo_coordinate_accepts_blank_and_numbers():
    assert parse_geo_coordinate("") is None
    assert parse_geo_coordinate(None) is None
    assert parse_geo_coordinate("12.75") == 12.75
    assert parse_geo_coordinate(8) == 8.0


def test_validate_tui_settings_requires_geo_coordinates():
    error = validate_tui_settings(
        {
            "mode": "mock",
            "sensor_id": "lab-geo",
            "interface": "",
            "pcap_path": "",
            "geo_enabled": True,
            "geo_sensor_x_m": "",
            "geo_sensor_y_m": "",
        }
    )

    assert error == "Geo-Location requires Sensor X/Y coordinates before startup."


def test_validate_tui_settings_accepts_valid_live_and_geo_inputs():
    error = validate_tui_settings(
        {
            "mode": "live",
            "sensor_id": "lab-live",
            "interface": "wlan0mon",
            "pcap_path": "",
            "geo_enabled": True,
            "geo_sensor_x_m": "1.5",
            "geo_sensor_y_m": "-2.0",
        },
        available_ifaces=["wlan0mon", "wlan1mon"],
    )

    assert error is None
