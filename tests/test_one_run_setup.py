from pathlib import Path

from sensor.one_run_setup import (
    STATE_VERSION,
    _entrypoint_matches_venv,
    build_local_only_lab_env,
    build_root_env,
    docker_daemon_accessible,
    build_state_payload,
    build_tui_profile_store,
    has_bootstrap_state,
    parse_env_file,
    render_config_yaml,
    write_helper_launchers,
    write_state_file,
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


def test_build_state_payload_tracks_generated_files(tmp_path: Path):
    payload = build_state_payload(
        sensor_id="lab-sensor-01",
        interface="wlan0mon",
        controller_url="http://127.0.0.1:8080/",
        lab_env_path=tmp_path / "ops" / ".env.lab",
    )

    assert payload["version"] == STATE_VERSION
    assert payload["bootstrap_mode"] == "full"
    assert payload["controller_url"] == "http://127.0.0.1:8080"
    assert payload["dashboard_url"] == "http://127.0.0.1:8080/dashboard/"
    assert ".sentinel_tui_profiles.json" in payload["generated_files"]


def test_entrypoint_matches_venv_detects_moved_virtualenv(tmp_path: Path):
    expected_python = tmp_path / "venv" / "bin" / "python"
    script_path = tmp_path / "venv" / "bin" / "pip"
    script_path.parent.mkdir(parents=True, exist_ok=True)

    script_path.write_text(
        "#!/old/workspace/venv/bin/python\nprint('broken')\n",
        encoding="utf-8",
    )
    assert _entrypoint_matches_venv(script_path, expected_python) is False

    script_path.write_text(
        f"#!{expected_python}\nprint('ok')\n",
        encoding="utf-8",
    )
    assert _entrypoint_matches_venv(script_path, expected_python) is True


def test_build_local_only_lab_env_contains_runtime_tokens():
    payload = build_local_only_lab_env()

    assert payload["DASH_USERNAME"] == "admin"
    assert payload["DASH_PASSWORD"] == ""
    assert payload["CONTROLLER_SECRET_KEY"]
    assert payload["CONTROLLER_HMAC_SECRET"]
    assert payload["DASHBOARD_API_TOKEN"]
    assert payload["SENSOR_AUTH_TOKEN"]


def test_docker_daemon_accessible_reports_missing_binary(monkeypatch):
    monkeypatch.setattr("sensor.one_run_setup.shutil.which", lambda _: None)

    ok, detail = docker_daemon_accessible()

    assert ok is False
    assert "not installed" in detail


class _DockerInfoFailure:
    returncode = 1
    stderr = "permission denied while trying to connect to the Docker daemon socket"


def test_docker_daemon_accessible_reports_permission_denied(monkeypatch):
    monkeypatch.setattr(
        "sensor.one_run_setup.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr(
        "sensor.one_run_setup.subprocess.run",
        lambda *args, **kwargs: _DockerInfoFailure(),
    )

    ok, detail = docker_daemon_accessible()

    assert ok is False
    assert "permission denied" in detail.lower()


def test_has_bootstrap_state_requires_state_file_and_generated_assets(tmp_path: Path):
    assert has_bootstrap_state(tmp_path) is False

    for name in (
        ".env",
        "config.yaml",
        ".sentinel_tui_profiles.json",
        "run_tui.sh",
        "open_dashboard.sh",
    ):
        (tmp_path / name).write_text("", encoding="utf-8")

    write_state_file(
        tmp_path / ".sentinel_one_run_state.json", {"version": STATE_VERSION}
    )

    assert has_bootstrap_state(tmp_path) is True


def test_write_helper_launchers_creates_scripts_with_custom_dashboard_url(
    tmp_path: Path,
):
    dashboard_url = "http://127.0.0.1:9090/dashboard/"
    write_helper_launchers(tmp_path, dashboard_url=dashboard_url)

    run_tui = tmp_path / "run_tui.sh"
    open_dashboard = tmp_path / "open_dashboard.sh"

    assert run_tui.exists()
    assert open_dashboard.exists()
    assert "python -m sensor.tui" in run_tui.read_text(encoding="utf-8")
    assert dashboard_url in open_dashboard.read_text(encoding="utf-8")
