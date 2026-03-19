"""
Helpers for loading and persisting TUI-facing configuration.

These utilities intentionally avoid importing Textual so they can be tested
without the optional UI dependency being installed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import yaml

from sensor.tui.setup_wizard import build_upload_url, normalize_controller_url

DEFAULT_CONFIG_FILENAMES = ("config.yaml", "config.yml", "config.example.yaml")
DEFAULT_SENSOR_ID = "tui-sensor-01"


def resolve_config_path(project_root: Path) -> Path | None:
    """Pick the first available project config file."""
    for name in DEFAULT_CONFIG_FILENAMES:
        candidate = project_root / name
        if candidate.exists():
            return candidate
    return None


def load_raw_config(config_path: Path | None) -> dict[str, Any]:
    """Read a raw config mapping without applying environment validation."""
    if config_path is None:
        return {}

    try:
        with open(config_path) as f:
            if config_path.suffix.lower() in {".yaml", ".yml"}:
                data = yaml.safe_load(f) or {}
            else:
                data = json.load(f)
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}


def load_saved_tui_settings(config_path: Path | None) -> dict[str, Any]:
    """Load only the fields the TUI needs for its setup screen."""
    data = load_raw_config(config_path)
    if not data:
        return {}

    capture = data.get("capture", {}) if isinstance(data.get("capture"), dict) else {}
    privacy = data.get("privacy", {}) if isinstance(data.get("privacy"), dict) else {}
    ml = data.get("ml", {}) if isinstance(data.get("ml"), dict) else {}
    geo = data.get("geo", {}) if isinstance(data.get("geo"), dict) else {}
    sensor = data.get("sensor", {}) if isinstance(data.get("sensor"), dict) else {}
    api = data.get("api", {}) if isinstance(data.get("api"), dict) else {}
    transport = (
        data.get("transport", {}) if isinstance(data.get("transport"), dict) else {}
    )

    interface = capture.get("interface") or sensor.get("interface") or ""
    mode = "mock" if data.get("mock_mode") else "live"
    pcap_path = capture.get("pcap_file")
    if pcap_path:
        mode = "pcap"

    upload_url = api.get("upload_url") or transport.get("upload_url")
    if upload_url:
        controller_url = normalize_controller_url(upload_url)
    elif api.get("host") and api.get("port"):
        controller_url = normalize_controller_url(f"http://{api['host']}:{api['port']}")
    else:
        controller_url = normalize_controller_url(None)

    return {
        "sensor_id": sensor.get("id", DEFAULT_SENSOR_ID),
        "interface": interface,
        "pcap_path": pcap_path or "",
        "controller_url": controller_url,
        "ml_enabled": bool(ml.get("enabled")),
        "geo_enabled": bool(geo.get("enabled")),
        "geo_sensor_x_m": _stringify_optional_number(geo.get("sensor_x_m")),
        "geo_sensor_y_m": _stringify_optional_number(geo.get("sensor_y_m")),
        "anonymize": bool(privacy.get("anonymize_ssid", True)),
        "mode": mode,
    }


def persist_tui_settings(
    project_root: Path,
    current_config_path: Path | None,
    settings: dict[str, Any],
) -> Path:
    """
    Persist the latest TUI setup values to a project config file.

    If the current source is `config.example.yaml` (or missing), write to
    `config.yaml` instead of mutating the example file.
    """
    target = _choose_write_target(project_root, current_config_path)
    data = load_raw_config(current_config_path)

    sensor = data.setdefault("sensor", {})
    capture = data.setdefault("capture", {})
    api = data.setdefault("api", {})
    ml = data.setdefault("ml", {})
    geo = data.setdefault("geo", {})
    privacy = data.setdefault("privacy", {})
    transport = data.get("transport")

    if not isinstance(sensor, dict):
        sensor = {}
        data["sensor"] = sensor
    if not isinstance(capture, dict):
        capture = {}
        data["capture"] = capture
    if not isinstance(api, dict):
        api = {}
        data["api"] = api
    if not isinstance(ml, dict):
        ml = {}
        data["ml"] = ml
    if not isinstance(geo, dict):
        geo = {}
        data["geo"] = geo
    if not isinstance(privacy, dict):
        privacy = {}
        data["privacy"] = privacy

    mode = str(settings.get("mode", "mock"))
    sensor["id"] = coerce_sensor_id(
        settings.get("sensor_id"),
        sensor.get("id", DEFAULT_SENSOR_ID),
    )

    interface = str(settings.get("interface", capture.get("interface", "wlan0")))
    if mode == "mock":
        capture["interface"] = interface or capture.get("interface", "wlan0")
        data["mock_mode"] = True
        capture["pcap_file"] = None
    elif mode == "pcap":
        capture["interface"] = interface or capture.get("interface", "pcap0")
        capture["pcap_file"] = str(settings.get("pcap_path", ""))
        data["mock_mode"] = False
    else:
        capture["interface"] = interface
        capture["pcap_file"] = None
        data["mock_mode"] = False

    ml["enabled"] = bool(settings.get("ml_enabled"))
    geo["enabled"] = bool(settings.get("geo_enabled"))
    geo["sensor_x_m"] = parse_geo_coordinate(settings.get("geo_sensor_x_m"))
    geo["sensor_y_m"] = parse_geo_coordinate(settings.get("geo_sensor_y_m"))
    privacy["anonymize_ssid"] = bool(settings.get("anonymize"))
    controller_url = normalize_controller_url(settings.get("controller_url"))
    api["upload_url"] = build_upload_url(controller_url)
    if isinstance(transport, dict):
        transport["upload_url"] = build_upload_url(controller_url)

    _write_config(target, data)
    return target


def _choose_write_target(project_root: Path, current_config_path: Path | None) -> Path:
    if current_config_path is None or current_config_path.name == "config.example.yaml":
        return project_root / "config.yaml"
    return current_config_path


def _write_config(target: Path, data: dict[str, Any]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w") as f:
        if target.suffix.lower() in {".yaml", ".yml"}:
            yaml.safe_dump(data, f, sort_keys=False)
        else:
            json.dump(data, f, indent=2)


def coerce_sensor_id(raw_value: Any, fallback: str = DEFAULT_SENSOR_ID) -> str:
    """Return a non-empty sensor id suitable for persistence/runtime use."""
    value = str(raw_value or "").strip()
    if value:
        return value
    return str(fallback or DEFAULT_SENSOR_ID)


def parse_geo_coordinate(raw_value: Any) -> float | None:
    """Parse a persisted Geo coordinate from UI text or config values."""
    if raw_value is None:
        return None
    if isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
        return float(raw_value)

    text = str(raw_value).strip()
    if not text:
        return None

    return float(text)


def validate_tui_settings(
    settings: dict[str, Any],
    available_ifaces: Sequence[str] | None = None,
    file_exists: Callable[[str], bool] | None = None,
) -> str | None:
    """Validate setup screen selections before launching the runtime worker."""
    mode = str(settings.get("mode", "mock")).strip().lower() or "mock"
    iface = str(settings.get("interface", "")).strip()
    pcap_path = str(settings.get("pcap_path", "")).strip()
    controller_url = normalize_controller_url(settings.get("controller_url"))
    geo_enabled = bool(settings.get("geo_enabled"))
    available = list(available_ifaces or [])
    file_exists = file_exists or (lambda path: Path(path).is_file())

    if not controller_url.startswith(("http://", "https://")):
        return "Controller URL must start with http:// or https://"

    if mode == "live":
        if not available or available[0] == "(none detected)":
            return (
                "No WiFi card detected. Please plug in a USB WiFi adapter "
                "or switch to Mock Mode."
            )
        if iface not in available:
            return f"Interface '{iface}' not found. Available: {', '.join(available)}"

    if mode == "pcap":
        if not pcap_path:
            return "PCAP mode requires a file path."
        if not file_exists(pcap_path):
            return f"File not found: {pcap_path}"

    if geo_enabled:
        try:
            x_coord = parse_geo_coordinate(settings.get("geo_sensor_x_m"))
            y_coord = parse_geo_coordinate(settings.get("geo_sensor_y_m"))
        except ValueError:
            return "Geo coordinates must be valid numbers (meters)."

        if x_coord is None or y_coord is None:
            return "Geo-Location requires Sensor X/Y coordinates before startup."

    return None


def _stringify_optional_number(raw_value: Any) -> str:
    if raw_value is None:
        return ""
    return str(raw_value)
