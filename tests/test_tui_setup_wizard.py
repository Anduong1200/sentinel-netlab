import json
from pathlib import Path

import pytest

from sensor.tui.setup_wizard import (
    DEFAULT_DEMO_SENSOR_ID,
    DEFAULT_DEMO_SENSOR_TOKEN,
    build_bootstrap_env,
    build_quick_profile,
    build_upload_url,
    coerce_live_sensor_id,
    normalize_controller_url,
    request_sensor_token,
    upsert_env_file,
)


def test_normalize_controller_url_strips_api_paths():
    assert normalize_controller_url("127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert (
        normalize_controller_url("https://controller.lab/api/v1/telemetry")
        == "https://controller.lab"
    )
    assert build_upload_url("https://controller.lab") == (
        "https://controller.lab/api/v1/telemetry"
    )


def test_build_quick_profile_demo_uses_safe_defaults():
    settings = build_quick_profile("demo", ["wlan1", "wlan0mon"])

    assert settings["mode"] == "mock"
    assert settings["sensor_id"] == DEFAULT_DEMO_SENSOR_ID
    assert settings["interface"] == "wlan0mon"
    assert settings["controller_url"] == "http://127.0.0.1:8080"
    assert settings["admin_token"] == "admin-token-dev"


def test_build_quick_profile_live_prefers_existing_sensor_label():
    settings = build_quick_profile(
        "live",
        ["wlan0", "wlan1mon"],
        current_sensor_id="Field Team / Sensor A",
        controller_url="https://controller.example",
    )

    assert settings["mode"] == "live"
    assert settings["sensor_id"] == "field-team-sensor-a"
    assert settings["interface"] == "wlan1mon"
    assert settings["anonymize"] is True
    assert settings["controller_url"] == "https://controller.example"


def test_coerce_live_sensor_id_falls_back_to_hostname():
    value = coerce_live_sensor_id("")
    assert value.startswith("sensor-")


def test_build_bootstrap_env_demo_keeps_dev_tokens_enabled():
    env_updates = build_bootstrap_env("demo", "sensor-01", "http://127.0.0.1:8080")

    assert env_updates["SENSOR_AUTH_TOKEN"] == DEFAULT_DEMO_SENSOR_TOKEN
    assert env_updates["ALLOW_DEV_TOKENS"] == "true"
    assert env_updates["REQUIRE_HMAC"] == "false"
    assert env_updates["SENSOR_HMAC_SECRET"] == env_updates["CONTROLLER_HMAC_SECRET"]
    assert env_updates["SENTINEL_ADMIN_TOKEN"] == "admin-token-dev"


def test_build_bootstrap_env_live_generates_strong_runtime_values():
    env_updates = build_bootstrap_env(
        "live",
        "sensor-field-01",
        "https://controller.example",
        existing={"DASH_USERNAME": "soc"},
    )

    assert env_updates["ENVIRONMENT"] == "field"
    assert env_updates["ALLOW_DEV_TOKENS"] == "false"
    assert env_updates["REQUIRE_HMAC"] == "true"
    assert env_updates["REQUIRE_TLS"] == "true"
    assert env_updates["SENSOR_VERIFY_SSL"] == "true"
    assert env_updates["DASH_USERNAME"] == "soc"
    assert len(env_updates["SENSOR_AUTH_TOKEN"]) >= 32


def test_upsert_env_file_replaces_and_appends_values(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("SENSOR_ID=old\nKEEP_ME=yes\n", encoding="utf-8")

    upsert_env_file(env_path, {"SENSOR_ID": "sensor-new", "CONTROLLER_URL": "http://x"})

    content = env_path.read_text(encoding="utf-8")
    assert "SENSOR_ID=sensor-new" in content
    assert "KEEP_ME=yes" in content
    assert "CONTROLLER_URL=http://x" in content


def test_request_sensor_token_uses_controller_api():
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"token": "sensor-live-token"}).encode("utf-8")

    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        seen["body"] = json.loads(request.data.decode("utf-8"))
        seen["timeout"] = timeout
        return FakeResponse()

    token = request_sensor_token(
        "https://controller.example",
        "admin-token",
        "sensor-live-01",
        opener=fake_urlopen,
    )

    assert token == "sensor-live-token"
    assert seen["url"] == "https://controller.example/api/v1/tokens"
    assert seen["body"]["sensor_id"] == "sensor-live-01"
    assert seen["timeout"] == 5


def test_request_sensor_token_requires_admin_token():
    with pytest.raises(RuntimeError, match="Admin token is required"):
        request_sensor_token("http://127.0.0.1:8080", "", "sensor-01")
