import json
from pathlib import Path

import yaml

from sensor.tui.config_store import (
    apply_tui_preset,
    coerce_sensor_id,
    delete_tui_profile,
    load_saved_tui_settings,
    load_tui_profile,
    parse_geo_coordinate,
    persist_tui_settings,
    resolve_config_path,
    resolve_profile_store_path,
    save_tui_profile,
    validate_tui_settings,
)


def test_resolve_prefers_real_config(tmp_path: Path):
    (tmp_path / "config.example.yaml").write_text("mock_mode: true\n")
    (tmp_path / "config.yaml").write_text("mock_mode: false\n")

    resolved = resolve_config_path(tmp_path)

    assert resolved == tmp_path / "config.yaml"


def test_persist_tui_settings_creates_project_config(tmp_path: Path):
    example = tmp_path / "config.example.yaml"
    sample_pcap = tmp_path / "sample.pcap"
    example.write_text("sensor:\n  id: demo\n")

    target = persist_tui_settings(
        project_root=tmp_path,
        current_config_path=example,
        settings={
            "mode": "pcap",
            "sensor_id": "lab-01",
            "interface": "wlan1mon",
            "pcap_path": str(sample_pcap),
            "capture_method": "tshark",
            "capture_channels": "1, 6, 11, 36, 40, 44",
            "dwell_ms": "250",
            "adaptive_hopping": True,
            "buffer_max_items": "50000",
            "buffer_drop_policy": "spill_to_disk",
            "ml_enabled": True,
            "geo_enabled": False,
            "anonymize": True,
            "scrub_probe_requests": False,
            "detector_profile": "full_wids",
            "det_profile": "full_wids",
            "preset_id": "soc_tactical",
        },
    )

    assert target == tmp_path / "config.yaml"
    data = yaml.safe_load(target.read_text())
    assert data["sensor"]["id"] == "lab-01"
    assert data["capture"]["interface"] == "wlan1mon"
    assert data["capture"]["pcap_file"] == str(sample_pcap)
    assert data["capture"]["method"] == "tshark"
    assert data["capture"]["channels"] == [1, 6, 11, 36, 40, 44]
    assert data["capture"]["adaptive_hopping"] is True
    assert data["buffer"]["max_items"] == 50000
    assert data["buffer"]["drop_policy"] == "spill_to_disk"
    assert data["mock_mode"] is False
    assert data["api"]["upload_url"] == "http://127.0.0.1:8080/api/v1/telemetry"
    assert data["ml"]["enabled"] is True
    assert data["privacy"]["anonymize_ssid"] is True
    assert data["privacy"]["scrub_probe_requests"] is False
    assert data["detectors"]["default_profile"] == "full_wids"
    assert data["tui"]["preset_id"] == "soc_tactical"


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
            "controller_url": "https://controller.lab:9443",
            "ml_enabled": False,
            "geo_enabled": True,
            "geo_sensor_x_m": "12.5",
            "geo_sensor_y_m": "4.0",
            "anonymize": False,
            "capture_method": "tshark",
            "capture_channels": "1, 6, 11, 36, 40, 44",
            "dwell_ms": "250",
            "adaptive_hopping": True,
            "buffer_max_items": "50000",
            "buffer_drop_policy": "spill_to_disk",
            "scrub_probe_requests": False,
            "detector_profile": "full_wids",
            "det_profile": "full_wids",
            "profile_name": "SOC Tactical Lab",
            "preset_id": "soc_tactical",
        },
    )

    settings = load_saved_tui_settings(config_path)

    assert settings["mode"] == "mock"
    assert settings["sensor_id"] == "lab-02"
    assert settings["interface"] == "wlan9mon"
    assert settings["controller_url"] == "https://controller.lab:9443"
    assert settings["geo_enabled"] is True
    assert settings["geo_sensor_x_m"] == "12.5"
    assert settings["geo_sensor_y_m"] == "4.0"
    assert settings["anonymize"] is False
    assert settings["capture_method"] == "tshark"
    assert settings["capture_channels"] == "1, 6, 11, 36, 40, 44"
    assert settings["dwell_ms"] == "250"
    assert settings["adaptive_hopping"] is True
    assert settings["buffer_max_items"] == "50000"
    assert settings["buffer_drop_policy"] == "spill_to_disk"
    assert settings["scrub_probe_requests"] is False
    assert settings["detector_profile"] == "full_wids"
    assert settings["profile_name"] == "SOC Tactical Lab"
    assert settings["preset_id"] == "soc_tactical"


def test_builtin_preset_can_be_saved_loaded_and_deleted(tmp_path: Path):
    settings = apply_tui_preset(
        "soc_tactical",
        {
            "sensor_id": "field-alpha",
            "interface": "wlan1mon",
            "controller_url": "https://controller.lab",
        },
    )

    saved_name = save_tui_profile(tmp_path, "SOC Tactical Lab", settings)

    assert saved_name == "SOC Tactical Lab"
    profile_store = json.loads(
        resolve_profile_store_path(tmp_path).read_text(encoding="utf-8")
    )
    assert "SOC Tactical Lab" in profile_store["profiles"]

    loaded = load_tui_profile(tmp_path, "SOC Tactical Lab")

    assert loaded is not None
    assert loaded["sensor_id"] == "field-alpha"
    assert loaded["capture_method"] == "tshark"
    assert loaded["buffer_drop_policy"] == "spill_to_disk"
    assert loaded["detector_profile"] == "full_wids"
    assert loaded["preset_id"] == "soc_tactical"

    assert delete_tui_profile(tmp_path, "SOC Tactical Lab") is True
    assert load_tui_profile(tmp_path, "SOC Tactical Lab") is None


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
            "controller_url": "http://127.0.0.1:8080",
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
            "controller_url": "https://controller.lab:9443",
            "geo_enabled": True,
            "geo_sensor_x_m": "1.5",
            "geo_sensor_y_m": "-2.0",
        },
        available_ifaces=["wlan0mon", "wlan1mon"],
    )

    assert error is None
