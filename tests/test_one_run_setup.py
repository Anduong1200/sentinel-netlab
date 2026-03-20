from pathlib import Path

from sensor.one_run_setup import (
    build_root_env,
    build_tui_profile_store,
    parse_env_file,
    render_config_yaml,
    write_helper_launchers,
)


def test_parse_env_file_ignores_comments_and_blank_lines(tmp_path: Path):
    env_path = tmp_path / ".env.lab"
    env_path.write_text(
        "# Comment\n\nSENSOR_AUTH_TOKEN=token-123\nDASH_USERNAME=admin\n",
        encoding="utf-8",
    )

    values = parse_env_file(env_path)

    assert values == {
        "SENSOR_AUTH_TOKEN": "token-123",
        "DASH_USERNAME": "admin",
    }


def test_build_root_env_maps_lab_values_for_tui_runtime():
    root_env = build_root_env(
        {
            "CONTROLLER_SECRET_KEY": "controller-secret",
            "CONTROLLER_HMAC_SECRET": "controller-hmac",
            "DASHBOARD_API_TOKEN": "dashboard-token",
            "SENSOR_AUTH_TOKEN": "sensor-runtime-token",
            "DASH_USERNAME": "soc",
            "DASH_PASSWORD": "pw123",
        },
        sensor_id="lab-sensor-01",
        controller_url="http://127.0.0.1:8080",
    )

    assert root_env["SENSOR_ID"] == "lab-sensor-01"
    assert root_env["SENSOR_AUTH_TOKEN"] == "sensor-runtime-token"
    assert root_env["SENSOR_HMAC_SECRET"] == "controller-hmac"
    assert root_env["SENTINEL_ADMIN_TOKEN"] == "admin-token-dev"
    assert root_env["SENTINEL_DASHBOARD_URL"] == "http://127.0.0.1:8080/dashboard/"


def test_render_config_yaml_includes_mock_mode_and_upload_url():
    rendered = render_config_yaml(
        sensor_id="lab-sensor-01",
        controller_url="http://127.0.0.1:8080",
        interface="wlan0mon",
    )

    assert 'id: "lab-sensor-01"' in rendered
    assert 'interface: "wlan0mon"' in rendered
    assert 'upload_url: "http://127.0.0.1:8080/api/v1/telemetry"' in rendered
    assert "mock_mode: true" in rendered
    assert 'profile_name: "Lab Demo"' in rendered


def test_build_tui_profile_store_contains_demo_and_live_profiles():
    payload = build_tui_profile_store(
        sensor_id="lab-sensor-01",
        controller_url="http://127.0.0.1:8080",
        interface="wlan0mon",
    )

    assert payload["version"] == 1
    profiles = payload["profiles"]
    assert "Lab Demo" in profiles
    assert "Lab Live" in profiles
    assert profiles["Lab Demo"]["mode"] == "mock"
    assert profiles["Lab Live"]["preset_id"] == "balanced_live"


def test_write_helper_launchers_creates_executable_scripts(tmp_path: Path):
    write_helper_launchers(tmp_path)

    run_tui = tmp_path / "run_tui.sh"
    open_dashboard = tmp_path / "open_dashboard.sh"

    assert run_tui.exists()
    assert open_dashboard.exists()
    assert "python -m sensor.tui" in run_tui.read_text(encoding="utf-8")
    assert "http://127.0.0.1:8080/dashboard/" in open_dashboard.read_text(
        encoding="utf-8"
    )
