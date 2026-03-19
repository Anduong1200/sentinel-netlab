"""
Helpers for the TUI setup wizard and one-click bootstrap flows.
"""

from __future__ import annotations

import json
import re
import secrets
import socket
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8080"
DEFAULT_ADMIN_TOKEN = "admin-token-dev"  # noqa: S105 - intentional dev bootstrap
DEFAULT_DEMO_SENSOR_ID = "sensor-01"
DEFAULT_DEMO_SENSOR_TOKEN = "sensor-01-token"  # noqa: S105 - intentional dev bootstrap


def normalize_controller_url(raw_value: str | None) -> str:
    """Normalize a controller URL down to a base origin."""
    text = str(raw_value or "").strip()
    if not text:
        text = DEFAULT_CONTROLLER_URL
    if "://" not in text:
        text = f"http://{text}"

    text = text.rstrip("/")
    known_suffixes = (
        "/api/v1/telemetry",
        "/api/v1/sensors",
        "/api/v1/tokens",
        "/api/v1/time",
        "/api/v1",
    )
    for suffix in known_suffixes:
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def build_upload_url(controller_url: str | None) -> str:
    """Build the telemetry ingest URL from a controller base URL."""
    return f"{normalize_controller_url(controller_url)}/api/v1/telemetry"


def choose_best_interface(available_ifaces: Sequence[str] | None) -> str:
    """Prefer monitor-mode interfaces when available."""
    for iface in available_ifaces or []:
        if iface and iface != "(none detected)" and "mon" in iface:
            return iface
    for iface in available_ifaces or []:
        if iface and iface != "(none detected)":
            return iface
    return "wlan0mon"


def coerce_live_sensor_id(raw_value: str | None) -> str:
    """Build a stable live-capture sensor id from a label or hostname."""
    text = str(raw_value or "").strip()
    if not text:
        text = f"sensor-{socket.gethostname()}"
    normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-_").lower()
    return normalized or "sensor-live"


def build_quick_profile(
    profile: str,
    available_ifaces: Sequence[str] | None = None,
    current_sensor_id: str | None = None,
    controller_url: str | None = None,
) -> dict[str, Any]:
    """Return UI settings for a one-click demo or live profile."""
    normalized_profile = str(profile).strip().lower()
    base_url = normalize_controller_url(controller_url)
    best_iface = choose_best_interface(available_ifaces)

    if normalized_profile == "demo":
        return {
            "mode": "mock",
            "sensor_id": DEFAULT_DEMO_SENSOR_ID,
            "interface": best_iface,
            "pcap_path": "",
            "ml_enabled": False,
            "geo_enabled": False,
            "geo_sensor_x_m": "",
            "geo_sensor_y_m": "",
            "anonymize": False,
            "controller_url": base_url,
            "admin_token": DEFAULT_ADMIN_TOKEN,
        }

    return {
        "mode": "live",
        "sensor_id": coerce_live_sensor_id(current_sensor_id),
        "interface": best_iface,
        "pcap_path": "",
        "ml_enabled": True,
        "geo_enabled": False,
        "geo_sensor_x_m": "",
        "geo_sensor_y_m": "",
        "anonymize": True,
        "controller_url": base_url,
        "admin_token": "",
    }


def generate_secret_hex(length: int = 32) -> str:
    """Generate a hex secret with a predictable number of characters."""
    if length <= 0:
        raise ValueError("length must be positive")
    bytes_needed = (length + 1) // 2
    return secrets.token_hex(bytes_needed)[:length]


def build_bootstrap_env(
    profile: str,
    sensor_id: str,
    controller_url: str | None,
    existing: Mapping[str, str] | None = None,
    *,
    sensor_token: str | None = None,
    admin_token: str | None = None,
) -> dict[str, str]:
    """Create an env bundle for fast demo/live setup."""
    existing = existing or {}
    normalized_profile = str(profile).strip().lower()
    base_url = normalize_controller_url(controller_url)
    verify_tls = base_url.startswith("https://")

    controller_secret = existing.get("CONTROLLER_SECRET_KEY") or generate_secret_hex(32)
    controller_hmac = (
        existing.get("CONTROLLER_HMAC_SECRET")
        or existing.get("SENSOR_HMAC_SECRET")
        or generate_secret_hex(64)
    )
    dashboard_token = existing.get("DASHBOARD_API_TOKEN") or generate_secret_hex(32)
    lab_api_key = existing.get("LAB_API_KEY") or generate_secret_hex(32)
    dash_password = existing.get("DASH_PASSWORD") or generate_secret_hex(16)
    dash_username = existing.get("DASH_USERNAME") or "admin"

    if normalized_profile == "demo":
        runtime_token = sensor_token or DEFAULT_DEMO_SENSOR_TOKEN
        env_name = "development"
        admin_value = (
            admin_token or existing.get("SENTINEL_ADMIN_TOKEN") or DEFAULT_ADMIN_TOKEN
        )
        allow_dev_tokens = "true"
        require_hmac = "false"
        require_tls = "false"
        verify_ssl = "false"
        sentinel_profile = "demo"
    else:
        runtime_token = sensor_token or generate_secret_hex(32)
        env_name = "field"
        admin_value = admin_token or existing.get("SENTINEL_ADMIN_TOKEN", "")
        allow_dev_tokens = "false"
        require_hmac = "true"
        require_tls = "true" if verify_tls else "false"
        verify_ssl = "true" if verify_tls else "false"
        sentinel_profile = "live"

    return {
        "ENVIRONMENT": env_name,
        "SENTINEL_PROFILE": sentinel_profile,
        "CONTROLLER_URL": base_url,
        "SENSOR_ID": sensor_id,
        "SENSOR_AUTH_TOKEN": runtime_token,
        "SENSOR_HMAC_SECRET": controller_hmac,
        "CONTROLLER_SECRET_KEY": controller_secret,
        "CONTROLLER_HMAC_SECRET": controller_hmac,
        "SENSOR_VERIFY_SSL": verify_ssl,
        "ALLOW_DEV_TOKENS": allow_dev_tokens,
        "REQUIRE_TLS": require_tls,
        "REQUIRE_HMAC": require_hmac,
        "DASH_USERNAME": dash_username,
        "DASH_PASSWORD": dash_password,
        "DASHBOARD_API_TOKEN": dashboard_token,
        "LAB_API_KEY": lab_api_key,
        "SENTINEL_ADMIN_TOKEN": admin_value,
    }


def upsert_env_file(path: Path, updates: Mapping[str, str]) -> Path:
    """Insert or replace env vars in a local dotenv file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    else:
        lines = [
            "# Sentinel NetLab runtime env",
            "# Generated by the TUI quick setup",
            "",
        ]

    updated_keys: set[str] = set()
    for index, line in enumerate(lines):
        for key, value in updates.items():
            if line.startswith(f"{key}="):
                lines[index] = f"{key}={value}"
                updated_keys.add(key)

    if lines and lines[-1] != "":
        lines.append("")

    for key, value in updates.items():
        if key not in updated_keys:
            lines.append(f"{key}={value}")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def request_sensor_token(
    controller_url: str,
    admin_token: str,
    sensor_id: str,
    *,
    token_name: str | None = None,
    opener: Any = urllib.request.urlopen,
) -> str:
    """Create a sensor token via the controller admin API."""
    admin_value = str(admin_token or "").strip()
    if not admin_value:
        raise RuntimeError("Admin token is required to create a sensor token.")

    payload = {
        "name": token_name or f"TUI Sensor {sensor_id}",
        "role": "sensor",
        "sensor_id": sensor_id,
    }
    req = urllib.request.Request(  # noqa: S310
        url=f"{normalize_controller_url(controller_url)}/api/v1/tokens",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {admin_value}",
            "Content-Type": "application/json",
        },
    )

    try:
        with opener(req, timeout=5) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Controller token API failed ({exc.code}): {details}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach controller: {exc.reason}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Controller token API returned invalid JSON: {raw}"
        ) from exc

    token = data.get("token")
    if not token:
        raise RuntimeError(f"Controller token API response missing token: {data}")
    return str(token)
