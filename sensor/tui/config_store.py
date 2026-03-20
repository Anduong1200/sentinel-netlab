"""
Helpers for loading and persisting TUI-facing configuration.

These utilities intentionally avoid importing Textual so they can be tested
without the optional UI dependency being installed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from sensor.tui.setup_wizard import (
    DEFAULT_PROD_HEALTH_URL,
    build_upload_url,
    normalize_controller_url,
    normalize_health_url,
)

DEFAULT_CONFIG_FILENAMES = ("config.yaml", "config.yml", "config.example.yaml")
DEFAULT_SENSOR_ID = "tui-sensor-01"
PROFILE_STORE_FILENAME = ".sentinel_tui_profiles.json"

DEFAULT_CAPTURE_CHANNELS = (1, 6, 11)
DEFAULT_CAPTURE_METHOD = "scapy"
DEFAULT_DWELL_MS = 200
DEFAULT_BUFFER_MAX_ITEMS = 10000
DEFAULT_BUFFER_DROP_POLICY = "oldest"
DEFAULT_DETECTOR_PROFILE = "lite_realtime"

BUILTIN_TUI_PRESETS: dict[str, dict[str, Any]] = {
    "balanced_live": {
        "label": "Balanced Live",
        "description": "Safer live monitoring with a modest buffer and lite detectors.",
        "settings": {
            "mode": "live",
            "capture_method": "scapy",
            "capture_channels": "1, 6, 11",
            "dwell_ms": "250",
            "adaptive_hopping": False,
            "buffer_max_items": "12000",
            "buffer_drop_policy": "oldest",
            "scrub_probe_requests": True,
            "detector_profile": "lite_realtime",
            "ml_enabled": True,
            "anonymize": True,
        },
    },
    "soc_tactical": {
        "label": "SOC Tactical",
        "description": "High-visibility triage preset for dense capture and threat review.",
        "settings": {
            "capture_method": "tshark",
            "capture_channels": "1, 6, 11, 36, 40, 44",
            "dwell_ms": "250",
            "adaptive_hopping": True,
            "buffer_max_items": "50000",
            "buffer_drop_policy": "spill_to_disk",
            "scrub_probe_requests": False,
            "detector_profile": "full_wids",
            "ml_enabled": True,
            "anonymize": False,
        },
    },
    "pcap_forensics": {
        "label": "PCAP Forensics",
        "description": "Replay-oriented preset tuned for offline exploit and chain analysis.",
        "settings": {
            "mode": "pcap",
            "capture_method": "tshark",
            "capture_channels": "1, 6, 11, 36, 40, 44",
            "dwell_ms": "250",
            "adaptive_hopping": False,
            "buffer_max_items": "50000",
            "buffer_drop_policy": "spill_to_disk",
            "scrub_probe_requests": False,
            "detector_profile": "audit_offline",
            "ml_enabled": True,
            "anonymize": False,
        },
    },
}


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


def default_tui_settings() -> dict[str, Any]:
    """Return the complete TUI settings payload with stable defaults."""
    return {
        "mode": "mock",
        "sensor_id": DEFAULT_SENSOR_ID,
        "interface": "",
        "pcap_path": "",
        "controller_url": normalize_controller_url(None),
        "ml_enabled": False,
        "geo_enabled": False,
        "geo_sensor_x_m": "",
        "geo_sensor_y_m": "",
        "anonymize": True,
        "capture_method": DEFAULT_CAPTURE_METHOD,
        "capture_channels": _stringify_channel_list(DEFAULT_CAPTURE_CHANNELS),
        "dwell_ms": str(DEFAULT_DWELL_MS),
        "adaptive_hopping": False,
        "buffer_max_items": str(DEFAULT_BUFFER_MAX_ITEMS),
        "buffer_drop_policy": DEFAULT_BUFFER_DROP_POLICY,
        "scrub_probe_requests": False,
        "detector_profile": DEFAULT_DETECTOR_PROFILE,
        "profile_name": "",
        "preset_id": "",
        "audit_profile": "home",
        "audit_output": "artifacts/audit_report.json",
        "audit_use_mock": True,
        "prod_health_url": DEFAULT_PROD_HEALTH_URL,
    }


def normalize_tui_settings(settings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Normalize a partial settings mapping into the TUI's full shape."""
    merged = default_tui_settings()
    raw = dict(settings or {})
    merged.update(raw)

    merged["mode"] = str(merged.get("mode", "mock") or "mock").strip().lower()
    merged["sensor_id"] = coerce_sensor_id(
        merged.get("sensor_id"),
        merged.get("sensor_id", DEFAULT_SENSOR_ID),
    )
    merged["interface"] = str(merged.get("interface", "") or "").strip()
    merged["pcap_path"] = str(merged.get("pcap_path", "") or "").strip()
    merged["controller_url"] = normalize_controller_url(merged.get("controller_url"))
    merged["ml_enabled"] = bool(merged.get("ml_enabled"))
    merged["geo_enabled"] = bool(merged.get("geo_enabled"))
    merged["geo_sensor_x_m"] = _stringify_optional_number(merged.get("geo_sensor_x_m"))
    merged["geo_sensor_y_m"] = _stringify_optional_number(merged.get("geo_sensor_y_m"))
    merged["anonymize"] = bool(merged.get("anonymize"))
    merged["capture_method"] = _coerce_capture_method(merged.get("capture_method"))
    merged["capture_channels"] = _stringify_channel_list(
        parse_channel_list(merged.get("capture_channels"))
    )
    merged["dwell_ms"] = str(
        _parse_positive_int(merged.get("dwell_ms"), default=DEFAULT_DWELL_MS)
    )
    merged["adaptive_hopping"] = bool(merged.get("adaptive_hopping"))
    merged["buffer_max_items"] = str(
        _parse_positive_int(
            merged.get("buffer_max_items"),
            default=DEFAULT_BUFFER_MAX_ITEMS,
        )
    )
    merged["buffer_drop_policy"] = _coerce_buffer_drop_policy(
        merged.get("buffer_drop_policy")
    )
    merged["scrub_probe_requests"] = bool(merged.get("scrub_probe_requests"))
    merged["detector_profile"] = str(
        merged.get("detector_profile") or DEFAULT_DETECTOR_PROFILE
    ).strip()
    merged["profile_name"] = _normalize_profile_name(merged.get("profile_name"))
    merged["preset_id"] = _normalize_preset_id(merged.get("preset_id"))
    merged["audit_profile"] = str(merged.get("audit_profile") or "home").strip()
    merged["audit_output"] = str(
        merged.get("audit_output") or "artifacts/audit_report.json"
    ).strip()
    merged["audit_use_mock"] = bool(merged.get("audit_use_mock", True))
    merged["prod_health_url"] = normalize_health_url(
        merged.get("prod_health_url") or DEFAULT_PROD_HEALTH_URL
    )
    return merged


def apply_tui_preset(
    preset_id: str,
    settings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Overlay a built-in tactical preset onto the current TUI settings."""
    normalized_preset_id = _normalize_preset_id(preset_id)
    preset = BUILTIN_TUI_PRESETS.get(normalized_preset_id)
    if preset is None:
        raise ValueError(f"Unknown TUI preset: {preset_id}")

    merged = normalize_tui_settings(settings)
    merged.update(preset["settings"])
    merged["preset_id"] = normalized_preset_id
    return normalize_tui_settings(merged)


def load_saved_tui_settings(config_path: Path | None) -> dict[str, Any]:
    """Load the settings the TUI needs for its setup screen."""
    defaults = default_tui_settings()
    data = load_raw_config(config_path)
    if not data:
        return defaults

    capture = data.get("capture", {}) if isinstance(data.get("capture"), dict) else {}
    privacy = data.get("privacy", {}) if isinstance(data.get("privacy"), dict) else {}
    ml = data.get("ml", {}) if isinstance(data.get("ml"), dict) else {}
    geo = data.get("geo", {}) if isinstance(data.get("geo"), dict) else {}
    sensor = data.get("sensor", {}) if isinstance(data.get("sensor"), dict) else {}
    api = data.get("api", {}) if isinstance(data.get("api"), dict) else {}
    transport = (
        data.get("transport", {}) if isinstance(data.get("transport"), dict) else {}
    )
    buffer = data.get("buffer", {}) if isinstance(data.get("buffer"), dict) else {}
    detectors = (
        data.get("detectors", {}) if isinstance(data.get("detectors"), dict) else {}
    )
    tui = data.get("tui", {}) if isinstance(data.get("tui"), dict) else {}

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

    dwell_ms = capture.get("dwell_ms")
    if dwell_ms is None and capture.get("dwell_time") is not None:
        dwell_ms = int(float(capture["dwell_time"]) * 1000)

    return normalize_tui_settings(
        {
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
            "capture_method": capture.get("method", DEFAULT_CAPTURE_METHOD),
            "capture_channels": _stringify_channel_list(
                capture.get("channels", DEFAULT_CAPTURE_CHANNELS)
            ),
            "dwell_ms": dwell_ms if dwell_ms is not None else DEFAULT_DWELL_MS,
            "adaptive_hopping": bool(capture.get("adaptive_hopping")),
            "buffer_max_items": buffer.get("max_items", DEFAULT_BUFFER_MAX_ITEMS),
            "buffer_drop_policy": buffer.get("drop_policy", DEFAULT_BUFFER_DROP_POLICY),
            "scrub_probe_requests": bool(privacy.get("scrub_probe_requests")),
            "detector_profile": detectors.get(
                "default_profile", DEFAULT_DETECTOR_PROFILE
            ),
            "profile_name": tui.get("profile_name", ""),
            "preset_id": tui.get("preset_id", ""),
            "audit_profile": tui.get("audit_profile", "home"),
            "audit_output": tui.get("audit_output", "artifacts/audit_report.json"),
            "audit_use_mock": tui.get("audit_use_mock", mode != "live"),
            "prod_health_url": tui.get(
                "prod_health_url",
                DEFAULT_PROD_HEALTH_URL,
            ),
        }
    )


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
    buffer = data.setdefault("buffer", {})
    detectors = data.setdefault("detectors", {})
    tui = data.setdefault("tui", {})

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
    if not isinstance(buffer, dict):
        buffer = {}
        data["buffer"] = buffer
    if not isinstance(detectors, dict):
        detectors = {}
        data["detectors"] = detectors
    if not isinstance(tui, dict):
        tui = {}
        data["tui"] = tui

    normalized = normalize_tui_settings(settings)
    mode = normalized["mode"]
    sensor["id"] = coerce_sensor_id(
        normalized.get("sensor_id"),
        sensor.get("id", DEFAULT_SENSOR_ID),
    )

    interface = str(normalized.get("interface", capture.get("interface", "wlan0")))
    if mode == "mock":
        capture["interface"] = interface or capture.get("interface", "wlan0")
        data["mock_mode"] = True
        capture["pcap_file"] = None
    elif mode == "pcap":
        capture["interface"] = interface or capture.get("interface", "pcap0")
        capture["pcap_file"] = str(normalized.get("pcap_path", ""))
        data["mock_mode"] = False
    else:
        capture["interface"] = interface
        capture["pcap_file"] = None
        data["mock_mode"] = False

    capture["method"] = normalized["capture_method"]
    capture["channels"] = parse_channel_list(normalized["capture_channels"])
    capture["dwell_ms"] = _parse_positive_int(
        normalized["dwell_ms"], default=DEFAULT_DWELL_MS
    )
    capture["adaptive_hopping"] = bool(normalized["adaptive_hopping"])

    buffer["max_items"] = _parse_positive_int(
        normalized["buffer_max_items"],
        default=DEFAULT_BUFFER_MAX_ITEMS,
    )
    buffer["drop_policy"] = normalized["buffer_drop_policy"]

    ml["enabled"] = bool(normalized["ml_enabled"])
    geo["enabled"] = bool(normalized["geo_enabled"])
    geo["sensor_x_m"] = parse_geo_coordinate(normalized.get("geo_sensor_x_m"))
    geo["sensor_y_m"] = parse_geo_coordinate(normalized.get("geo_sensor_y_m"))
    privacy["anonymize_ssid"] = bool(normalized["anonymize"])
    privacy["scrub_probe_requests"] = bool(normalized["scrub_probe_requests"])
    detectors["default_profile"] = str(normalized["detector_profile"])

    controller_url = normalize_controller_url(normalized.get("controller_url"))
    api["upload_url"] = build_upload_url(controller_url)
    if isinstance(transport, dict):
        transport["upload_url"] = build_upload_url(controller_url)

    profile_name = normalized.get("profile_name", "")
    if profile_name:
        tui["profile_name"] = profile_name
    else:
        tui.pop("profile_name", None)

    preset_id = normalized.get("preset_id", "")
    if preset_id:
        tui["preset_id"] = preset_id
    else:
        tui.pop("preset_id", None)

    audit_profile = str(normalized.get("audit_profile", "")).strip()
    if audit_profile:
        tui["audit_profile"] = audit_profile
    else:
        tui.pop("audit_profile", None)

    audit_output = str(normalized.get("audit_output", "")).strip()
    if audit_output:
        tui["audit_output"] = audit_output
    else:
        tui.pop("audit_output", None)

    tui["audit_use_mock"] = bool(normalized.get("audit_use_mock", True))
    tui["prod_health_url"] = normalize_health_url(
        normalized.get("prod_health_url") or DEFAULT_PROD_HEALTH_URL
    )

    _write_config(target, data)
    return target


def resolve_profile_store_path(project_root: Path) -> Path:
    """Return the repo-local path used for saved TUI profiles."""
    return project_root / PROFILE_STORE_FILENAME


def list_saved_tui_profiles(project_root: Path) -> list[str]:
    """List all saved custom TUI profile names."""
    return sorted(_load_profile_store(project_root), key=str.casefold)


def load_tui_profile(project_root: Path, name: str) -> dict[str, Any] | None:
    """Load a named custom TUI profile, if it exists."""
    normalized_name = _normalize_profile_name(name)
    if not normalized_name:
        return None
    return _load_profile_store(project_root).get(normalized_name)


def save_tui_profile(project_root: Path, name: str, settings: Mapping[str, Any]) -> str:
    """Save the current TUI settings as a reusable named profile."""
    normalized_name = _normalize_profile_name(name)
    if not normalized_name:
        raise ValueError("Profile name is required.")

    profiles = _load_profile_store(project_root)
    profile_settings = normalize_tui_settings(settings)
    profile_settings["profile_name"] = normalized_name
    profiles[normalized_name] = profile_settings
    _write_profile_store(project_root, profiles)
    return normalized_name


def delete_tui_profile(project_root: Path, name: str) -> bool:
    """Delete a named custom TUI profile."""
    normalized_name = _normalize_profile_name(name)
    if not normalized_name:
        return False

    profiles = _load_profile_store(project_root)
    removed = profiles.pop(normalized_name, None) is not None
    if removed:
        _write_profile_store(project_root, profiles)
    return removed


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


def parse_channel_list(raw_value: Any) -> list[int]:
    """Parse a UI string or config list into a channel plan."""
    if isinstance(raw_value, Sequence) and not isinstance(raw_value, str | bytes):
        items = raw_value
    else:
        text = str(raw_value or "").strip()
        if not text:
            return list(DEFAULT_CAPTURE_CHANNELS)
        items = [item.strip() for item in text.strip("[]").split(",")]

    channels: list[int] = []
    for item in items:
        if item in ("", None):
            continue
        channel = int(item)
        if channel <= 0:
            raise ValueError("Channel numbers must be positive integers.")
        channels.append(channel)

    return channels or list(DEFAULT_CAPTURE_CHANNELS)


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

    capture_method = _coerce_capture_method(settings.get("capture_method"))
    if capture_method not in {"scapy", "tshark", "pcap"}:
        return "Capture method must be one of: scapy, tshark, pcap."

    try:
        parse_channel_list(settings.get("capture_channels"))
    except ValueError:
        return "Capture channels must be a comma-separated list of positive integers."

    try:
        _parse_positive_int(settings.get("dwell_ms"), default=DEFAULT_DWELL_MS)
    except ValueError:
        return "Dwell time must be a positive integer (milliseconds)."

    try:
        _parse_positive_int(
            settings.get("buffer_max_items"),
            default=DEFAULT_BUFFER_MAX_ITEMS,
        )
    except ValueError:
        return "Buffer size must be a positive integer."

    if _coerce_buffer_drop_policy(settings.get("buffer_drop_policy")) not in {
        "oldest",
        "spill_to_disk",
    }:
        return "Buffer drop policy must be either 'oldest' or 'spill_to_disk'."

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


def _load_profile_store(project_root: Path) -> dict[str, dict[str, Any]]:
    path = resolve_profile_store_path(project_root)
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    if not isinstance(raw, dict):
        return {}

    payload = raw.get("profiles", raw)
    if not isinstance(payload, dict):
        return {}

    profiles: dict[str, dict[str, Any]] = {}
    for name, settings in payload.items():
        normalized_name = _normalize_profile_name(name)
        if not normalized_name or not isinstance(settings, dict):
            continue
        normalized_settings = normalize_tui_settings(settings)
        normalized_settings["profile_name"] = normalized_name
        profiles[normalized_name] = normalized_settings
    return profiles


def _write_profile_store(
    project_root: Path,
    profiles: Mapping[str, dict[str, Any]],
) -> None:
    path = resolve_profile_store_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "profiles": {
            name: normalize_tui_settings(settings)
            for name, settings in profiles.items()
        },
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _normalize_profile_name(raw_value: Any) -> str:
    text = " ".join(str(raw_value or "").strip().split())
    if not text:
        return ""
    allowed_chars = []
    for char in text:
        if char.isalnum() or char in {" ", "-", "_"}:
            allowed_chars.append(char)
    normalized = "".join(allowed_chars).strip()
    return normalized[:48]


def _normalize_preset_id(raw_value: Any) -> str:
    text = str(raw_value or "").strip().lower()
    if text in BUILTIN_TUI_PRESETS:
        return text
    return ""


def _stringify_optional_number(raw_value: Any) -> str:
    if raw_value is None:
        return ""
    return str(raw_value)


def _stringify_channel_list(raw_value: Sequence[int] | Any) -> str:
    channels = parse_channel_list(raw_value)
    return ", ".join(str(channel) for channel in channels)


def _parse_positive_int(raw_value: Any, *, default: int) -> int:
    text = str(raw_value or "").strip()
    if not text:
        return default

    value = int(text)
    if value <= 0:
        raise ValueError("value must be positive")
    return value


def _coerce_capture_method(raw_value: Any) -> str:
    text = str(raw_value or DEFAULT_CAPTURE_METHOD).strip().lower()
    if text in {"scapy", "tshark", "pcap"}:
        return text
    return DEFAULT_CAPTURE_METHOD


def _coerce_buffer_drop_policy(raw_value: Any) -> str:
    text = str(raw_value or DEFAULT_BUFFER_DROP_POLICY).strip().lower()
    if text in {"oldest", "spill_to_disk"}:
        return text
    return DEFAULT_BUFFER_DROP_POLICY
