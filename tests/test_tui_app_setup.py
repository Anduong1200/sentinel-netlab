import asyncio
import os
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import Input

import sensor.tui.app as app_mod

BOOTSTRAP_ENV_KEYS = {
    "ENVIRONMENT",
    "SENTINEL_PROFILE",
    "CONTROLLER_URL",
    "SENSOR_ID",
    "SENSOR_AUTH_TOKEN",
    "SENSOR_HMAC_SECRET",
    "CONTROLLER_SECRET_KEY",
    "CONTROLLER_HMAC_SECRET",
    "SENSOR_VERIFY_SSL",
    "ALLOW_DEV_TOKENS",
    "REQUIRE_TLS",
    "REQUIRE_HMAC",
    "DASH_USERNAME",
    "DASH_PASSWORD",
    "DASHBOARD_API_TOKEN",
    "LAB_API_KEY",
    "SENTINEL_ADMIN_TOKEN",
}


def _snapshot_env() -> dict[str, str | None]:
    return {key: os.environ.get(key) for key in BOOTSTRAP_ENV_KEYS}


def _restore_env(snapshot: dict[str, str | None]) -> None:
    for key, value in snapshot.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_setup_screen_focuses_first_input_and_hides_optional_rows(
    monkeypatch, tmp_path: Path
):
    snapshot = _snapshot_env()

    async def run_case():
        monkeypatch.setattr(app_mod, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(app_mod, "detect_wifi_interfaces", lambda: ["wlan0mon"])
        monkeypatch.setattr(
            app_mod,
            "check_controller_online",
            lambda base_url=None: False,
        )

        app = app_mod.SentinelTUIApp()
        app.saved_settings = {
            "mode": "mock",
            "sensor_id": "sensor-01",
            "interface": "wlan0mon",
            "controller_url": "http://127.0.0.1:8080",
            "geo_enabled": False,
            "anonymize": True,
        }
        app.config_path = None

        async with app.run_test(size=(80, 24)):
            screen = app.screen
            assert type(screen).__name__ == "SetupScreen"
            assert app.focused is not None
            assert app.focused.id == "input-sensor-id"
            assert screen.query_one("#row-pcap").display is False
            assert screen.query_one("#row-geo-x").display is False
            assert screen.query_one("#row-geo-y").display is False

    try:
        asyncio.run(run_case())
    finally:
        _restore_env(snapshot)


def test_quick_demo_bundle_writes_env_and_updates_setup_fields(
    monkeypatch, tmp_path: Path
):
    snapshot = _snapshot_env()

    async def run_case():
        monkeypatch.setattr(app_mod, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(app_mod, "detect_wifi_interfaces", lambda: ["wlan0mon"])
        monkeypatch.setattr(
            app_mod,
            "check_controller_online",
            lambda base_url=None: False,
        )

        app = app_mod.SentinelTUIApp()
        app.saved_settings = {}
        app.config_path = None

        async with app.run_test(size=(100, 30)):
            screen = app.screen
            screen._apply_quick_bundle("demo")

            env_path = tmp_path / ".env"
            config_path = tmp_path / "config.yaml"

            assert env_path.exists()
            assert config_path.exists()
            assert screen.query_one("#input-sensor-id", Input).value == "sensor-01"
            assert (
                screen.query_one("#input-admin-token", Input).value == "admin-token-dev"
            )
            env_text = env_path.read_text(encoding="utf-8")
            assert "ALLOW_DEV_TOKENS=true" in env_text
            assert "SENSOR_AUTH_TOKEN=sensor-01-token" in env_text

    try:
        asyncio.run(run_case())
    finally:
        _restore_env(snapshot)


def test_generate_token_and_keys_uses_controller_when_available(
    monkeypatch, tmp_path: Path
):
    snapshot = _snapshot_env()

    async def run_case():
        monkeypatch.setattr(app_mod, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(app_mod, "detect_wifi_interfaces", lambda: ["wlan0mon"])
        monkeypatch.setattr(
            app_mod,
            "check_controller_online",
            lambda base_url=None: True,
        )
        monkeypatch.setattr(
            app_mod,
            "request_sensor_token",
            lambda controller_url, admin_token, sensor_id: "controller-issued-token",
        )

        app = app_mod.SentinelTUIApp()
        app.saved_settings = {
            "mode": "live",
            "sensor_id": "sensor-live-01",
            "interface": "wlan0mon",
            "controller_url": "http://127.0.0.1:8080",
        }
        app.config_path = None

        async with app.run_test(size=(100, 30)):
            screen = app.screen
            screen.query_one("#input-admin-token", Input).value = "admin-token"
            screen._generate_token_and_keys()

            env_text = (tmp_path / ".env").read_text(encoding="utf-8")
            assert "SENSOR_AUTH_TOKEN=controller-issued-token" in env_text
            assert "SENTINEL_ADMIN_TOKEN=admin-token" in env_text

    try:
        asyncio.run(run_case())
    finally:
        _restore_env(snapshot)
