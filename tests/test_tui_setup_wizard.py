import json
from pathlib import Path

import pytest

import sensor.tui.setup_wizard as wizard
from sensor.tui.setup_wizard import (
    DEFAULT_DEMO_SENSOR_ID,
    DEFAULT_DEMO_SENSOR_TOKEN,
    CommandResult,
    build_bootstrap_env,
    build_quick_profile,
    build_upload_url,
    coerce_live_sensor_id,
    collect_backend_health,
    detect_wireless_inventory,
    normalize_controller_url,
    request_sensor_token,
    run_lab_action,
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


def test_collect_backend_health_summarizes_runtime_readiness(monkeypatch):
    tools = {
        "make": "/usr/bin/make",
        "docker": "/usr/bin/docker",
        "iw": "/usr/bin/iw",
        "iwconfig": "/usr/bin/iwconfig",
        "lsusb": "/usr/bin/lsusb",
    }
    modules = {"sensor", "controller", "dashboard", "textual", "yaml", "dotenv"}

    monkeypatch.setattr(
        wizard.shutil,
        "which",
        lambda name: tools.get(name),
    )
    monkeypatch.setattr(
        wizard.importlib.util,
        "find_spec",
        lambda name: object() if name in modules else None,
    )
    monkeypatch.setattr(
        wizard,
        "_run_command",
        lambda args, **kwargs: CommandResult(
            ok=True,
            summary="docker ready",
            stdout="Server Version: test",
        ),
    )
    monkeypatch.setattr(
        wizard, "_probe_controller_health", lambda *args, **kwargs: True
    )

    report = collect_backend_health("http://controller.lab:8080")

    assert report.docker_ready is True
    assert report.controller_online is True
    assert report.command_status["iwconfig"] is True
    assert report.module_status["controller"] is True
    assert "controller online" in report.summary


def test_detect_wireless_inventory_prefers_monitor_interface(monkeypatch):
    responses = {
        ("lsusb",): CommandResult(
            ok=True,
            summary="usb",
            stdout="Bus 001 Device 002: ID 0cf3:9271 Atheros Adapter\n",
        ),
        ("iw", "dev"): CommandResult(
            ok=True,
            summary="iw",
            stdout=(
                "phy#0\n"
                "\tInterface wlan0\n"
                "\t\ttype managed\n"
                "\tInterface wlan0mon\n"
                "\t\ttype monitor\n"
            ),
        ),
        ("iwconfig",): CommandResult(
            ok=True,
            summary="iwconfig",
            stdout=(
                "wlan0     IEEE 802.11  Mode:Managed\n"
                "wlan0mon  IEEE 802.11  Mode:Monitor\n"
            ),
        ),
    }

    monkeypatch.setattr(
        wizard,
        "_run_command",
        lambda args, **kwargs: responses[tuple(args)],
    )
    monkeypatch.setattr(
        wizard,
        "_list_sysfs_wireless_interfaces",
        lambda: ["wlan0", "wlan0mon"],
    )

    report = detect_wireless_inventory()

    assert report.selected_interface == "wlan0mon"
    assert "Atheros" in report.usb_summary
    assert "wlan0mon:monitor" in report.interface_summary


def test_run_lab_action_autofills_live_settings_and_reads_env(
    monkeypatch, tmp_path: Path
):
    ops_dir = tmp_path / "ops"
    ops_dir.mkdir()
    (ops_dir / ".env.lab").write_text(
        "SENSOR_AUTH_TOKEN=lab-sensor-token\n"
        "DASH_USERNAME=admin\n"
        "DASH_PASSWORD=lab-pass\n",
        encoding="utf-8",
    )

    seen: dict[str, object] = {}

    monkeypatch.setattr(wizard.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run_command(args, **kwargs):
        seen["args"] = list(args)
        seen["cwd"] = kwargs.get("cwd")
        return CommandResult(ok=True, summary="ok", stdout="Lab started")

    monkeypatch.setattr(wizard, "_run_command", fake_run_command)

    report = run_lab_action(
        tmp_path,
        "generate_tokens",
        sensor_id="Field Team A",
        controller_url="http://controller.lab:8080",
    )

    assert report.ok is True
    assert seen["args"] == [
        "/usr/bin/make",
        "lab-gen-runtime-tokens",
        "SENSOR_ID=field-team-a",
    ]
    assert seen["cwd"] == tmp_path
    assert report.summary == "Lab generate_tokens completed."
    assert report.lab_env["SENSOR_AUTH_TOKEN"] == "lab-sensor-token"
    assert report.suggested_settings["sensor_id"] == "field-team-a"
    assert report.suggested_settings["controller_url"] == "http://controller.lab:8080"
