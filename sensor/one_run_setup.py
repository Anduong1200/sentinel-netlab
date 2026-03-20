#!/usr/bin/env python3
"""
One-run bootstrap for Sentinel NetLab after a fresh clone.

Goal:
- Create/reuse the local virtual environment
- Install runtime dependencies
- Bootstrap the lab stack (controller + dashboard + dependencies)
- Generate lab/runtime secrets and host-side TUI config
- Produce easy launchers so the user can just open the TUI or dashboard
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8080"
DEFAULT_DASHBOARD_URL = f"{DEFAULT_CONTROLLER_URL}/dashboard/"
DEFAULT_SENSOR_ID = "lab-sensor-01"
DEFAULT_INTERFACE = "wlan0mon"
DEFAULT_RUNTIME_PROFILE = "Lab Demo"
STATE_FILENAME = ".sentinel_one_run_state.json"
STATE_VERSION = 1


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def detect_compose_command() -> list[str]:
    """Return the supported Docker Compose command."""
    docker = shutil.which("docker")
    if docker:
        try:
            subprocess.run(
                [docker, "compose", "version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return [docker, "compose"]
        except subprocess.CalledProcessError:
            pass

    legacy = shutil.which("docker-compose")
    if legacy:
        try:
            subprocess.run(
                [legacy, "version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return [legacy]
        except subprocess.CalledProcessError:
            pass

    raise RuntimeError(
        "Docker Compose was not found. Install Docker Desktop or docker-compose."
    )


def run_command(command: list[str], cwd: Path) -> None:
    print(f"[one-run] $ {' '.join(command)}")
    subprocess.run(command, cwd=cwd, check=True)


def _entrypoint_matches_venv(script_path: Path, expected_python: Path) -> bool:
    """Return True when a venv launcher script still targets this repo-local Python."""
    if not script_path.exists():
        return False

    first_lines = script_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not first_lines:
        return False
    return first_lines[0].strip() == f"#!{expected_python}"


def ensure_venv(root: Path, python_executable: str) -> Path:
    """Create or repair the repo venv and return its Python path."""
    venv_dir = root / "venv"
    venv_python = venv_dir / "bin" / "python"
    pip_launcher = venv_dir / "bin" / "pip"

    needs_rebuild = not venv_python.exists()
    if not needs_rebuild and not _entrypoint_matches_venv(pip_launcher, venv_python):
        print("[one-run] Detected a stale moved venv. Rebuilding local virtualenv...")
        needs_rebuild = True

    if needs_rebuild:
        command = [python_executable, "-m", "venv"]
        if venv_dir.exists():
            command.append("--clear")
        command.append(str(venv_dir))
        run_command(command, cwd=root)
    return venv_python


def install_runtime(root: Path, venv_python: Path) -> None:
    """Install the runtime pieces required for TUI, controller, and dashboard."""
    run_command(
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "wheel"],
        cwd=root,
    )
    run_command(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "-e",
            ".[sensor,controller,dashboard]",
        ],
        cwd=root,
    )


def wait_for_http(url: str, *, timeout_sec: int = 180, interval_sec: int = 3) -> None:
    """Wait until an HTTP endpoint becomes available."""
    deadline = time.time() + timeout_sec
    last_error = "not started"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
                if response.status < 500:
                    return
        except urllib.error.URLError as exc:
            last_error = str(exc.reason)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(interval_sec)

    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def parse_env_file(path: Path) -> dict[str, str]:
    """Read a simple dotenv file into a mapping."""
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def write_env_file(path: Path, updates: dict[str, str]) -> None:
    """Write a deterministic repo-local dotenv file."""
    header = [
        "# Sentinel NetLab local runtime env",
        "# Generated by python -m sensor.one_run_setup",
        "",
    ]
    lines = header + [f"{key}={value}" for key, value in updates.items()]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def build_root_env(
    lab_env: dict[str, str],
    *,
    sensor_id: str,
    controller_url: str,
) -> dict[str, str]:
    """Build the host-side env used by the TUI and local sensor runtime."""
    required_keys = (
        "CONTROLLER_SECRET_KEY",
        "CONTROLLER_HMAC_SECRET",
        "DASHBOARD_API_TOKEN",
        "SENSOR_AUTH_TOKEN",
    )
    missing = [key for key in required_keys if not lab_env.get(key)]
    if missing:
        raise RuntimeError(
            f"ops/.env.lab is missing required keys after bootstrap: {', '.join(missing)}"
        )

    return {
        "ENVIRONMENT": "development",
        "SENTINEL_PROFILE": "lab",
        "CONTROLLER_URL": controller_url,
        "SENSOR_ID": sensor_id,
        "SENSOR_AUTH_TOKEN": lab_env["SENSOR_AUTH_TOKEN"],
        "SENSOR_HMAC_SECRET": lab_env["CONTROLLER_HMAC_SECRET"],
        "CONTROLLER_SECRET_KEY": lab_env["CONTROLLER_SECRET_KEY"],
        "CONTROLLER_HMAC_SECRET": lab_env["CONTROLLER_HMAC_SECRET"],
        "SENSOR_VERIFY_SSL": "false",
        "ALLOW_DEV_TOKENS": "true",
        "REQUIRE_TLS": "false",
        "REQUIRE_HMAC": "false",
        "SENTINEL_ADMIN_TOKEN": "admin-token-dev",
        "DASHBOARD_API_TOKEN": lab_env["DASHBOARD_API_TOKEN"],
        "DASH_USERNAME": lab_env.get("DASH_USERNAME", "admin"),
        "DASH_PASSWORD": lab_env.get("DASH_PASSWORD", ""),
        "SENTINEL_DASHBOARD_URL": f"{controller_url}/dashboard/",
    }


def render_config_yaml(
    *,
    sensor_id: str,
    controller_url: str,
    interface: str,
) -> str:
    """Render a safe default config for host-side TUI usage."""
    upload_url = f"{controller_url.rstrip('/')}/api/v1/telemetry"
    return textwrap.dedent(
        f"""
        sensor:
          id: "{sensor_id}"

        capture:
          interface: "{interface}"
          method: "scapy"
          channels: [1, 6, 11]
          dwell_ms: 250
          adaptive_hopping: false
          pcap_file: null

        buffer:
          max_items: 12000
          drop_policy: "oldest"

        api:
          upload_url: "{upload_url}"

        upload:
          batch_size: 200
          interval_sec: 5.0

        ml:
          enabled: false

        geo:
          enabled: false
          sensor_x_m: null
          sensor_y_m: null

        privacy:
          anonymize_ssid: true
          scrub_probe_requests: true

        detectors:
          default_profile: "lite_realtime"

        mock_mode: true

        tui:
          profile_name: "{DEFAULT_RUNTIME_PROFILE}"
          preset_id: ""
        """
    ).lstrip()


def build_tui_profile_store(
    *,
    sensor_id: str,
    controller_url: str,
    interface: str,
) -> dict[str, object]:
    """Return a profile store payload compatible with the TUI."""
    return {
        "version": 1,
        "profiles": {
            "Lab Demo": {
                "profile_name": "Lab Demo",
                "preset_id": "",
                "mode": "mock",
                "sensor_id": sensor_id,
                "interface": interface,
                "pcap_path": "",
                "controller_url": controller_url,
                "ml_enabled": False,
                "geo_enabled": False,
                "geo_sensor_x_m": "",
                "geo_sensor_y_m": "",
                "anonymize": True,
                "capture_method": "scapy",
                "capture_channels": "1, 6, 11",
                "dwell_ms": "250",
                "adaptive_hopping": False,
                "buffer_max_items": "12000",
                "buffer_drop_policy": "oldest",
                "scrub_probe_requests": True,
                "detector_profile": "lite_realtime",
            },
            "Lab Live": {
                "profile_name": "Lab Live",
                "preset_id": "balanced_live",
                "mode": "live",
                "sensor_id": sensor_id,
                "interface": interface,
                "pcap_path": "",
                "controller_url": controller_url,
                "ml_enabled": True,
                "geo_enabled": False,
                "geo_sensor_x_m": "",
                "geo_sensor_y_m": "",
                "anonymize": True,
                "capture_method": "scapy",
                "capture_channels": "1, 6, 11",
                "dwell_ms": "250",
                "adaptive_hopping": False,
                "buffer_max_items": "12000",
                "buffer_drop_policy": "oldest",
                "scrub_probe_requests": True,
                "detector_profile": "lite_realtime",
            },
        },
    }


def write_profile_store(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build_local_only_lab_env() -> dict[str, str]:
    """Generate a local-only env bundle for mock/TUI bootstrap."""
    return {
        "CONTROLLER_SECRET_KEY": secrets.token_hex(16),
        "CONTROLLER_HMAC_SECRET": secrets.token_hex(32),
        "DASHBOARD_API_TOKEN": secrets.token_hex(16),
        "SENSOR_AUTH_TOKEN": secrets.token_hex(16),
        "DASH_USERNAME": "admin",
        "DASH_PASSWORD": "",
    }


def has_python_module(python_executable: Path, module_name: str) -> bool:
    """Return True when a module is importable inside the repo venv."""
    result = subprocess.run(
        [str(python_executable), "-c", f"import {module_name}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def docker_daemon_accessible() -> tuple[bool, str]:
    """Return whether the current user can talk to the Docker daemon."""
    docker = shutil.which("docker")
    if not docker:
        return False, "Docker Engine is not installed on this host."

    result = subprocess.run(
        [docker, "info"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        return True, ""

    detail = (result.stderr or "").strip() or "docker info failed"
    return False, detail


def build_state_payload(
    *,
    sensor_id: str,
    interface: str,
    controller_url: str,
    lab_env_path: Path,
    bootstrap_mode: str = "full",
) -> dict[str, object]:
    """Serialize the local bootstrap state so reruns can stay lightweight."""
    return {
        "version": STATE_VERSION,
        "bootstrap_mode": bootstrap_mode,
        "sensor_id": sensor_id,
        "interface": interface,
        "controller_url": controller_url.rstrip("/"),
        "dashboard_url": f"{controller_url.rstrip('/')}/dashboard/",
        "lab_env_path": str(lab_env_path),
        "generated_files": [
            ".env",
            "config.yaml",
            ".sentinel_tui_profiles.json",
            "run_tui.sh",
            "open_dashboard.sh",
        ],
    }


def write_local_runtime_bundle(
    *,
    root: Path,
    sensor_id: str,
    interface: str,
    controller_url: str,
    lab_env: dict[str, str],
    bootstrap_mode: str,
) -> None:
    """Write host-side runtime files for either full or TUI-only bootstrap."""
    write_env_file(
        root / ".env",
        build_root_env(
            lab_env,
            sensor_id=sensor_id,
            controller_url=controller_url,
        ),
    )
    (root / "config.yaml").write_text(
        render_config_yaml(
            sensor_id=sensor_id,
            controller_url=controller_url,
            interface=interface,
        ),
        encoding="utf-8",
    )
    write_profile_store(
        root / ".sentinel_tui_profiles.json",
        build_tui_profile_store(
            sensor_id=sensor_id,
            controller_url=controller_url,
            interface=interface,
        ),
    )
    write_helper_launchers(
        root, dashboard_url=f"{controller_url.rstrip('/')}/dashboard/"
    )
    write_state_file(
        root / STATE_FILENAME,
        build_state_payload(
            sensor_id=sensor_id,
            interface=interface,
            controller_url=controller_url,
            lab_env_path=root / "ops" / ".env.lab",
            bootstrap_mode=bootstrap_mode,
        ),
    )


def write_state_file(path: Path, payload: dict[str, object]) -> None:
    """Persist bootstrap metadata for later reruns and support checks."""
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def has_bootstrap_state(root: Path) -> bool:
    """Return True when a previous one-run bootstrap is already present."""
    state_path = root / STATE_FILENAME
    if not state_path.exists():
        return False

    required_paths = (
        root / ".env",
        root / "config.yaml",
        root / ".sentinel_tui_profiles.json",
        root / "run_tui.sh",
        root / "open_dashboard.sh",
    )
    return all(path.exists() for path in required_paths)


def write_helper_launchers(
    root: Path, *, dashboard_url: str = DEFAULT_DASHBOARD_URL
) -> None:
    run_tui = root / "run_tui.sh"
    run_tui.write_text(
        textwrap.dedent(
            """
            #!/usr/bin/env bash
            set -euo pipefail
            cd "$(dirname "$0")"
            source venv/bin/activate
            python -m sensor.tui
            """
        ).lstrip(),
        encoding="utf-8",
    )
    run_tui.chmod(0o755)

    open_dashboard = root / "open_dashboard.sh"
    open_dashboard.write_text(
        textwrap.dedent(
            f"""
            #!/usr/bin/env bash
            set -euo pipefail
            python - <<'PY'
            import webbrowser
            url = "{dashboard_url}"
            print(f"Opening {{url}}")
            webbrowser.open(url)
            PY
            """
        ).lstrip(),
        encoding="utf-8",
    )
    open_dashboard.chmod(0o755)


def bootstrap_lab(
    *,
    root: Path,
    sensor_id: str,
    interface: str,
    controller_url: str,
    seed_data: bool,
    build_images: bool,
    open_browser: bool,
    launch_tui: bool,
    force: bool,
) -> None:
    venv_python = ensure_venv(root, sys.executable)
    reuse_existing = has_bootstrap_state(root) and not force
    if reuse_existing:
        print(
            "[one-run] Existing bootstrap detected. Reusing local files and skipping "
            "dependency reinstall/demo reseed. Pass --force to rebuild everything."
        )
    else:
        install_runtime(root, venv_python)

    if not has_python_module(venv_python, "pytest"):
        print(
            "[one-run] Preflight: pytest/dev tooling is not installed in this venv. "
            'Install `python -m pip install -e ".[dev,controller,sensor,dashboard]"` '
            "if you want local tests, linting, and mypy."
        )

    compose_error: str | None = None
    try:
        compose = detect_compose_command()
    except RuntimeError as exc:
        compose = None
        compose_error = str(exc)
    else:
        docker_ready, docker_error = docker_daemon_accessible()
        if not docker_ready:
            compose = None
            compose_error = docker_error

    if compose is None:
        write_local_runtime_bundle(
            root=root,
            sensor_id=sensor_id,
            interface=interface,
            controller_url=controller_url,
            lab_env=build_local_only_lab_env(),
            bootstrap_mode="tui_only",
        )
        print("")
        print(
            f"[one-run] {compose_error or 'Docker Compose is not available on this host.'}"
        )
        print(
            "[one-run] Falling back to a TUI-only bootstrap so you can still use "
            "Mock / Test mode right away."
        )
        print(f"[one-run] TUI launcher: {root / 'run_tui.sh'}")
        print(
            "[one-run] Install Docker Desktop or docker-compose later, then rerun "
            "`python one_run.py --force` for the full dashboard/controller stack."
        )
        if compose_error and "permission denied" in compose_error.lower():
            print(
                "[one-run] Hint: add your user to the `docker` group with "
                "`sudo usermod -aG docker $USER`, then re-login or run `newgrp docker`."
            )
        if open_browser:
            print(
                "[one-run] Skipping browser launch because the dashboard stack is offline."
            )
        if launch_tui:
            run_command([str(root / "run_tui.sh")], cwd=root)
        return

    run_command([str(venv_python), "ops/gen_lab_secrets.py"], cwd=root)

    compose_file = root / "ops" / "docker-compose.lab.yml"
    lab_env_path = root / "ops" / ".env.lab"
    up_command = compose + [
        "--env-file",
        str(lab_env_path),
        "-f",
        str(compose_file),
        "up",
        "-d",
        "--remove-orphans",
    ]
    if build_images:
        up_command.insert(-2, "--build")
    run_command(up_command, cwd=root)

    wait_for_http(f"{controller_url.rstrip('/')}/api/v1/health")

    exec_prefix = compose + [
        "--env-file",
        str(lab_env_path),
        "-f",
        str(compose_file),
        "exec",
        "-T",
    ]
    run_command(exec_prefix + ["controller", "python", "ops/init_lab_db.py"], cwd=root)

    if seed_data and not reuse_existing:
        run_command(
            compose
            + [
                "--env-file",
                str(lab_env_path),
                "-f",
                str(compose_file),
                "run",
                "--rm",
                "seed",
            ],
            cwd=root,
        )

    run_command(
        [
            str(venv_python),
            "ops/gen_lab_runtime_tokens.py",
            "--base-url",
            controller_url,
            "--sensor-id",
            sensor_id,
            "--env-file",
            str(lab_env_path),
        ],
        cwd=root,
    )

    run_command(
        compose
        + [
            "--env-file",
            str(lab_env_path),
            "-f",
            str(compose_file),
            "up",
            "-d",
            "dashboard",
        ],
        cwd=root,
    )

    subprocess.run(
        compose
        + [
            "--env-file",
            str(lab_env_path),
            "-f",
            str(compose_file),
            "stop",
            "sensor",
        ],
        cwd=root,
        check=False,
    )

    write_local_runtime_bundle(
        root=root,
        sensor_id=sensor_id,
        interface=interface,
        controller_url=controller_url,
        lab_env=parse_env_file(lab_env_path),
        bootstrap_mode="full",
    )

    print("")
    print("[one-run] Bootstrap complete.")
    print(f"[one-run] Dashboard: {controller_url}/dashboard/")
    print(f"[one-run] TUI launcher: {root / 'run_tui.sh'}")
    print(f"[one-run] Browser launcher: {root / 'open_dashboard.sh'}")
    print(f"[one-run] State file: {root / STATE_FILENAME}")
    print("[one-run] Next time you usually only need: ./run_tui.sh")

    if open_browser:
        webbrowser.open(f"{controller_url.rstrip('/')}/dashboard/")

    if launch_tui:
        run_command([str(root / "run_tui.sh")], cwd=root)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="One-run bootstrap for Sentinel NetLab after a fresh clone.",
    )
    parser.add_argument("--sensor-id", default=DEFAULT_SENSOR_ID)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--controller-url", default=DEFAULT_CONTROLLER_URL)
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="Skip the demo data seed step.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip docker image rebuilds during compose up.",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the dashboard URL in the default browser when done.",
    )
    parser.add_argument(
        "--launch-tui",
        action="store_true",
        help="Launch the TUI automatically when bootstrap completes.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall dependencies and reseed demo data even if local bootstrap files already exist.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        bootstrap_lab(
            root=repo_root(),
            sensor_id=args.sensor_id,
            interface=args.interface,
            controller_url=args.controller_url.rstrip("/"),
            seed_data=not args.no_seed,
            build_images=not args.no_build,
            open_browser=args.open_browser,
            launch_tui=args.launch_tui,
            force=args.force,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[one-run] Command failed with exit code {exc.returncode}: {exc.cmd}")
        return exc.returncode or 1
    except RuntimeError as exc:
        print(f"[one-run] ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
