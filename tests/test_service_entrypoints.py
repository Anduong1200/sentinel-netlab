from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_systemd_units_use_supported_sensor_entrypoint():
    unit_paths = [
        PROJECT_ROOT / "ops" / "sentinel-sensor.service",
        PROJECT_ROOT / "ops" / "systemd" / "sentinel-sensor.service",
    ]

    for unit_path in unit_paths:
        content = unit_path.read_text()
        assert "--config-file" in content
        assert "Restart=on-failure" in content
        assert "RestartSec=5s" in content
        assert "StartLimitIntervalSec=300" in content
        assert "StartLimitBurst=3" in content


def test_unified_script_monitor_command_loads_cli_help():
    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "sentinel.py"), "monitor", "--help"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=False,
    )

    assert result.returncode == 0
    assert "sentinel-sensor" in result.stdout
    assert "--config-file" in result.stdout
