"""
Helpers for the TUI setup wizard and one-click bootstrap flows.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import subprocess  # nosec B404
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8080"
DEFAULT_LAB_CONTROLLER_URL = "http://127.0.0.1:8080"
DEFAULT_PROD_HEALTH_URL = "http://127.0.0.1/health"
DEFAULT_ADMIN_TOKEN = "admin-token-dev"  # noqa: S105 - intentional dev bootstrap
DEFAULT_DEMO_SENSOR_ID = "sensor-01"
DEFAULT_DEMO_SENSOR_TOKEN = "sensor-01-token"  # noqa: S105 - intentional dev bootstrap
_AUDIT_PROFILE_ALIASES = {
    "enterprise": "sme",
    "home": "home",
    "small-business": "sme",
    "sme": "sme",
    "soho": "home",
}
_WIRELESS_HINTS = (
    "atheros",
    "mediatek",
    "ralink",
    "realtek",
    "qualcomm",
    "intel",
    "broadcom",
    "alfa",
)
_INSTALL_TARGETS: dict[str, tuple[str, str]] = {
    "sensor": (".[sensor]", "Sensor"),
    "controller": (".[controller]", "Controller"),
    "engine": (".[dashboard,ml]", "Engine"),
    "full": (".[sensor,controller,dashboard,ml]", "Full Stack"),
}


@dataclass(frozen=True)
class CommandResult:
    """Normalized subprocess execution result."""

    ok: bool
    summary: str
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class BackendCheckReport:
    """High-level dependency and backend readiness summary."""

    command_status: dict[str, bool]
    module_status: dict[str, bool]
    docker_ready: bool
    controller_online: bool
    controller_url: str
    summary: str


@dataclass(frozen=True)
class WirelessInterfaceCandidate:
    """Wireless interface detected from iw/iwconfig/sysfs."""

    name: str
    mode: str
    source: str


@dataclass(frozen=True)
class WirelessInventoryReport:
    """Detailed USB + wireless interface inventory for setup autofill."""

    interfaces: tuple[WirelessInterfaceCandidate, ...]
    selected_interface: str
    usb_summary: str
    interface_summary: str
    summary: str


@dataclass(frozen=True)
class LabActionReport:
    """Outcome of a lab-management action launched from the setup screen."""

    action: str
    ok: bool
    summary: str
    details: str
    suggested_settings: dict[str, str] = field(default_factory=dict)
    lab_env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditRunReport:
    """Structured security audit result for the TUI."""

    ok: bool
    summary: str
    profile: str
    output_path: Path
    report_data: dict[str, Any]
    networks_scanned: int
    duration_sec: float


@dataclass(frozen=True)
class DeploymentActionReport:
    """Outcome of a production deployment action launched from the TUI."""

    action: str
    ok: bool
    summary: str
    details: str
    env_file: Path | None = None
    health_url: str = DEFAULT_PROD_HEALTH_URL
    health_ok: bool = False


def _run_command(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int = 30,
) -> CommandResult:
    """Execute a command and normalize common failures for UI consumption."""
    try:
        completed = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        command = args[0] if args else "command"
        return CommandResult(
            ok=False,
            summary=f"Command not found: {command}",
            returncode=127,
            stderr=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(
            ok=False,
            summary=f"Timed out while running: {' '.join(args)}",
            returncode=124,
            stdout=stdout,
            stderr=stderr,
        )

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    summary = (
        stdout.splitlines()[-1] if stdout else stderr.splitlines()[-1] if stderr else ""
    )
    return CommandResult(
        ok=completed.returncode == 0,
        summary=summary or f"Command exited with {completed.returncode}",
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple dotenv file into a mapping."""
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def build_lab_autofill_settings(
    sensor_id: str,
    controller_url: str | None = None,
) -> dict[str, str]:
    """Return a live-capture autofill bundle after lab bootstrap succeeds."""
    return {
        "mode": "live",
        "sensor_id": coerce_live_sensor_id(sensor_id),
        "controller_url": normalize_controller_url(
            controller_url or DEFAULT_LAB_CONTROLLER_URL
        ),
        "admin_token": DEFAULT_ADMIN_TOKEN,
    }


def _probe_controller_health(
    controller_url: str,
    opener: Any = urllib.request.urlopen,
) -> bool:
    """Check the controller health endpoint with a short timeout."""
    health_url = f"{normalize_controller_url(controller_url)}/api/v1/health"
    try:
        with opener(health_url, timeout=2) as response:  # noqa: S310
            return bool(response.getcode() == 200)
    except Exception:
        return False


def collect_backend_health(
    controller_url: str | None,
    *,
    opener: Any = urllib.request.urlopen,
) -> BackendCheckReport:
    """Inspect runtime prerequisites for the TUI's sensor/controller flows."""
    command_status = {
        "make": shutil.which("make") is not None,
        "docker": shutil.which("docker") is not None,
        "iw": shutil.which("iw") is not None,
        "iwconfig": shutil.which("iwconfig") is not None,
        "lsusb": shutil.which("lsusb") is not None,
    }
    module_status = {
        "sensor": importlib.util.find_spec("sensor") is not None,
        "controller": importlib.util.find_spec("controller") is not None,
        "dashboard": importlib.util.find_spec("dashboard") is not None,
        "textual": importlib.util.find_spec("textual") is not None,
        "yaml": importlib.util.find_spec("yaml") is not None,
        "dotenv": importlib.util.find_spec("dotenv") is not None,
    }
    docker_ready = False
    if command_status["docker"]:
        docker_ready = _run_command(["docker", "info"], timeout=10).ok

    normalized_url = normalize_controller_url(controller_url)
    controller_online = _probe_controller_health(normalized_url, opener=opener)

    missing_modules = [
        name.title()
        for name in ("sensor", "controller", "dashboard")
        if not module_status[name]
    ]
    summary_parts = [
        "docker ready" if docker_ready else "docker offline",
        "controller online" if controller_online else "controller offline",
        "wifi tooling ready"
        if command_status["iw"] and command_status["iwconfig"]
        else "wifi tooling incomplete",
    ]
    if missing_modules:
        summary_parts.append(f"missing python extras: {', '.join(missing_modules)}")

    return BackendCheckReport(
        command_status=command_status,
        module_status=module_status,
        docker_ready=docker_ready,
        controller_online=controller_online,
        controller_url=normalized_url,
        summary=" | ".join(summary_parts),
    )


def install_python_component(
    project_root: Path,
    component: str,
    *,
    python_executable: str | None = None,
) -> CommandResult:
    """Install a repo-local optional dependency bundle via pip."""
    normalized_component = str(component).strip().lower()
    if normalized_component not in _INSTALL_TARGETS:
        raise ValueError(f"Unknown install target: {component}")

    extras, label = _INSTALL_TARGETS[normalized_component]
    result = _run_command(
        [
            python_executable or sys.executable,
            "-m",
            "pip",
            "install",
            "-e",
            extras,
        ],
        cwd=project_root,
        timeout=1800,
    )
    summary = (
        f"{label} dependencies installed."
        if result.ok
        else f"{label} install failed: {result.summary}"
    )
    return CommandResult(
        ok=result.ok,
        summary=summary,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def run_lab_action(
    project_root: Path,
    action: str,
    *,
    sensor_id: str,
    controller_url: str | None = None,
) -> LabActionReport:
    """Run a repo-provided lab shortcut and expose autofill data to the TUI."""
    normalized_action = str(action).strip().lower()
    make_binary = shutil.which("make") or "make"
    command_map: dict[str, list[str]] = {
        "up": [make_binary, "lab-up"],
        "down": [make_binary, "lab-down"],
        "reset": [make_binary, "lab-reset"],
        "status": [make_binary, "lab-status"],
        "generate_tokens": [
            make_binary,
            "lab-gen-runtime-tokens",
            f"SENSOR_ID={coerce_live_sensor_id(sensor_id)}",
        ],
    }
    if normalized_action not in command_map:
        raise ValueError(f"Unknown lab action: {action}")

    result = _run_command(
        command_map[normalized_action], cwd=project_root, timeout=1800
    )
    lab_env = parse_env_file(project_root / "ops" / ".env.lab")
    suggested_settings = {}
    if result.ok and normalized_action != "down":
        suggested_settings = build_lab_autofill_settings(sensor_id, controller_url)

    details = "\n".join(
        chunk for chunk in (result.stdout, result.stderr) if chunk
    ).strip()
    return LabActionReport(
        action=normalized_action,
        ok=result.ok,
        summary=(
            f"Lab {normalized_action} completed."
            if result.ok
            else f"Lab {normalized_action} failed: {result.summary}"
        ),
        details=details or result.summary,
        suggested_settings=suggested_settings,
        lab_env=lab_env,
    )


def run_tests(
    project_root: Path, python_executable: str | None = None
) -> CommandResult:
    """Run the pytest suite and return a summarized result."""
    # Ensure pytest is available
    pytest_bin = shutil.which("pytest") or "pytest"
    if python_executable:
        args = [python_executable, "-m", "pytest", "tests/"]
    else:
        args = [pytest_bin, "tests/"]

    result = _run_command(args, cwd=project_root, timeout=300)
    summary = "All tests passed." if result.ok else "Some tests failed or errored."
    if not result.ok and "collected 0 items" in result.stdout:
        summary = "No tests found in tests/."

    return CommandResult(
        ok=result.ok,
        summary=summary,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def normalize_audit_profile(raw_value: str | None) -> str:
    """Map user-friendly audit profile labels onto supported checklist names."""
    normalized = str(raw_value or "").strip().lower()
    if not normalized:
        return "home"
    return _AUDIT_PROFILE_ALIASES.get(normalized, normalized)


def normalize_health_url(raw_value: str | None) -> str:
    """Normalize a deployment health URL and add a sensible default path."""
    text = str(raw_value or "").strip()
    if not text:
        text = DEFAULT_PROD_HEALTH_URL
    if "://" not in text:
        text = f"http://{text}"
    if "/" not in text.split("://", 1)[1]:
        text = f"{text.rstrip('/')}/health"
    return text.rstrip("/")


def probe_health_endpoint(
    url: str | None,
    *,
    opener: Any = urllib.request.urlopen,
    attempts: int = 1,
    delay_sec: float = 0.0,
) -> bool:
    """Probe an arbitrary HTTP health endpoint with lightweight retries."""
    target_url = normalize_health_url(url)
    tries = max(attempts, 1)
    for attempt in range(tries):
        try:
            with opener(target_url, timeout=2) as response:  # noqa: S310
                if response.getcode() == 200:
                    return True
        except Exception:  # noqa: S110
            pass
        if attempt < tries - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    return False


def resolve_test_targets(
    *,
    include_unit: bool,
    include_integration: bool,
    include_all: bool,
) -> tuple[str, ...]:
    """Resolve checkbox state into pytest target directories."""
    if include_all or (not include_unit and not include_integration):
        return ("tests/",)

    targets: list[str] = []
    if include_unit:
        targets.append("tests/unit")
    if include_integration:
        targets.append("tests/integration")
    return tuple(targets)


def build_pytest_command(
    test_targets: Sequence[str],
    *,
    python_executable: str | None = None,
) -> list[str]:
    """Build a pytest command for streaming diagnostics from the TUI."""
    targets = list(test_targets) or ["tests/"]
    return [python_executable or sys.executable, "-m", "pytest", *targets]


def run_security_audit(
    project_root: Path,
    *,
    profile: str,
    output_path: str | Path,
    sensor_id: str,
    iface: str,
    use_mock: bool,
    progress: Callable[[str], None] | None = None,
) -> AuditRunReport:
    """Run the Wi-Fi security audit and return structured report data."""
    from sensor.audit import _perform_discovery
    from sensor.auditor import ReportGenerator, SecurityAuditor, scan_mock_networks

    def emit(message: str) -> None:
        if progress is not None:
            progress(message)

    normalized_profile = normalize_audit_profile(profile)
    if normalized_profile not in {"home", "sme"}:
        raise ValueError(
            f"Unsupported audit profile '{profile}'. Use home, sme, or enterprise."
        )

    resolved_output_path = Path(output_path)
    if not resolved_output_path.is_absolute():
        resolved_output_path = project_root / resolved_output_path
    resolved_output_path.parent.mkdir(parents=True, exist_ok=True)
    report_format = "html" if resolved_output_path.suffix.lower() == ".html" else "json"

    emit(f"Loaded profile '{normalized_profile}'.")
    auditor = SecurityAuditor(sensor_id, profile=normalized_profile)

    started = time.perf_counter()
    if use_mock:
        emit("Using mock discovery dataset.")
        networks = scan_mock_networks()
    else:
        emit(f"Scanning interface {iface} for nearby networks.")
        networks = _perform_discovery(iface)

    emit(f"Discovered {len(networks)} networks.")
    for network in networks:
        ssid = network.ssid or "[Hidden]"
        emit(f"Auditing {ssid} ({network.bssid}).")
        auditor.audit_network(network)

    duration_sec = time.perf_counter() - started
    report_data = auditor.generate_report_data(duration_sec)
    ReportGenerator().save_report(
        report_data,
        resolved_output_path,
        format=report_format,
    )

    counts = report_data["summary"]["counts"]
    summary = (
        f"{report_data['summary']['networks_scanned']} networks | "
        f"critical {counts.get('critical', 0)} | "
        f"high {counts.get('high', 0)} | "
        f"medium {counts.get('medium', 0)} | "
        f"low {counts.get('low', 0)}"
    )
    emit(f"Saved audit report to {resolved_output_path}.")

    return AuditRunReport(
        ok=True,
        summary=summary,
        profile=normalized_profile,
        output_path=resolved_output_path,
        report_data=report_data,
        networks_scanned=int(report_data["summary"]["networks_scanned"]),
        duration_sec=duration_sec,
    )


def build_sensor_daemon_command(
    settings: Mapping[str, Any],
    *,
    config_path: Path | None,
    python_executable: str | None = None,
) -> list[str]:
    """Build a detached `sensor.cli` command that mirrors TUI settings."""
    mode = str(settings.get("mode", "mock")).strip().lower()
    sensor_id = str(settings.get("sensor_id") or coerce_live_sensor_id(""))
    interface = str(settings.get("interface") or "wlan0mon").strip() or "wlan0mon"
    command = [python_executable or sys.executable, "-m", "sensor.cli"]

    if config_path is not None:
        command.extend(["--config-file", str(config_path)])

    command.extend(["--sensor-id", sensor_id])
    if mode == "mock":
        command.extend(["--iface", "mock0", "--mock-mode"])
    else:
        command.extend(["--iface", interface])
        if mode == "pcap":
            pcap_path = str(settings.get("pcap_path") or "").strip()
            if pcap_path:
                command.extend(["--pcap", pcap_path])

    upload_url = build_upload_url(str(settings.get("controller_url") or ""))
    if upload_url:
        command.extend(["--upload-url", upload_url])
    if bool(settings.get("ml_enabled")):
        command.append("--enable-ml")
    if bool(settings.get("geo_enabled")):
        command.append("--enable-geo")
    if bool(settings.get("anonymize", True)):
        command.append("--anonymize-ssid")

    return command


def resolve_prod_env_file(project_root: Path) -> Path | None:
    """Locate the production dotenv file expected by the compose stack."""
    candidates = (
        project_root / "ops" / ".env",
        project_root / "ops" / ".env.prod",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def run_prod_action(
    project_root: Path,
    action: str,
    *,
    health_url: str | None = None,
) -> DeploymentActionReport:
    """Run a production compose action and report stack health."""
    normalized_action = str(action).strip().lower()
    if normalized_action not in {"up", "down", "status"}:
        raise ValueError(f"Unknown production action: {action}")

    env_file = resolve_prod_env_file(project_root)
    if env_file is None:
        return DeploymentActionReport(
            action=normalized_action,
            ok=False,
            summary="Missing production env file. Create ops/.env from ops/.env.prod.example first.",
            details="Expected ops/.env (preferred) or ops/.env.prod for docker compose.",
            env_file=None,
            health_url=normalize_health_url(health_url),
            health_ok=False,
        )

    compose_args = [
        "docker",
        "compose",
        "--env-file",
        str(env_file.relative_to(project_root)),
        "-f",
        "ops/docker-compose.prod.yml",
    ]
    action_args = {
        "down": ["down"],
        "status": ["ps"],
        "up": ["up", "-d"],
    }[normalized_action]
    result = _run_command(
        [*compose_args, *action_args],
        cwd=project_root,
        timeout=1800,
    )

    target_health_url = normalize_health_url(health_url)
    health_ok = False
    if result.ok and normalized_action == "up":
        health_ok = probe_health_endpoint(
            target_health_url,
            attempts=10,
            delay_sec=2.0,
        )
    elif normalized_action == "status":
        health_ok = probe_health_endpoint(target_health_url)

    details = "\n".join(
        chunk for chunk in (result.stdout, result.stderr) if chunk
    ).strip()
    if normalized_action == "up":
        summary = (
            "Production stack deployed and health endpoint is reachable."
            if result.ok and health_ok
            else "Production stack deployed, but health endpoint is not ready yet."
            if result.ok
            else f"Production deploy failed: {result.summary}"
        )
    elif normalized_action == "down":
        summary = (
            "Production stack stopped."
            if result.ok
            else f"Production stop failed: {result.summary}"
        )
    else:
        if result.ok:
            summary = (
                "Production stack is healthy."
                if health_ok
                else "Production stack status collected; health endpoint is unreachable."
            )
        else:
            summary = f"Production status failed: {result.summary}"

    return DeploymentActionReport(
        action=normalized_action,
        ok=result.ok,
        summary=summary,
        details=details or result.summary,
        env_file=env_file,
        health_url=target_health_url,
        health_ok=health_ok,
    )


def open_dashboard_gui(url: str | None) -> CommandResult:
    """Open the controller/dashboard URL with the platform GUI launcher."""
    target_url = normalize_controller_url(url or DEFAULT_LAB_CONTROLLER_URL)
    launchers = (
        ["xdg-open", target_url],
        ["gio", "open", target_url],
        ["open", target_url],
    )
    for launcher in launchers:
        if shutil.which(launcher[0]) is None:
            continue
        result = _run_command(launcher, timeout=10)
        if result.ok:
            return CommandResult(ok=True, summary=f"Opened GUI at {target_url}")
        return CommandResult(
            ok=False,
            summary=f"GUI launch failed: {result.summary}",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    return CommandResult(
        ok=False,
        summary="No GUI launcher found (xdg-open, gio, or open).",
        returncode=127,
    )


def _parse_iw_dev_interfaces(text: str) -> dict[str, str]:
    """Parse interface name -> mode from `iw dev` output."""
    interfaces: dict[str, str] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Interface "):
            current = line.split(maxsplit=1)[1]
            interfaces.setdefault(current, "unknown")
            continue
        if current and line.startswith("type "):
            interfaces[current] = line.split(maxsplit=1)[1].strip().lower()
    return interfaces


def _parse_iwconfig_interfaces(text: str) -> dict[str, str]:
    """Parse interface name -> mode from `iwconfig` output."""
    interfaces: dict[str, str] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        if raw_line and not raw_line[0].isspace():
            header = re.match(r"^([A-Za-z0-9_.:-]+)\s+IEEE 802\.11", raw_line)
            current = header.group(1) if header is not None else None
            if current:
                mode_match = re.search(r"Mode:([A-Za-z]+)", raw_line)
                interfaces[current] = (
                    mode_match.group(1).strip().lower()
                    if mode_match is not None
                    else "wireless"
                )
            continue
        if current and current in interfaces:
            mode_match = re.search(r"Mode:([A-Za-z]+)", raw_line)
            if mode_match is not None:
                interfaces[current] = mode_match.group(1).strip().lower()
    return interfaces


def _list_sysfs_wireless_interfaces() -> list[str]:
    """Fallback wireless discovery via sysfs when iw tools are unavailable."""
    sysfs_root = Path("/sys/class/net")
    if not sysfs_root.exists():
        return []

    interfaces: list[str] = []
    for candidate in sysfs_root.iterdir():
        if (candidate / "wireless").exists() or (candidate / "phy80211").exists():
            interfaces.append(candidate.name)
    return sorted(set(interfaces))


def _summarize_usb_inventory(text: str) -> str:
    """Compress relevant lsusb lines into a short status string."""
    matches = [
        line.strip()
        for line in text.splitlines()
        if any(hint in line.lower() for hint in _WIRELESS_HINTS)
    ]
    if matches:
        return "; ".join(matches[:2])
    stripped = [line.strip() for line in text.splitlines() if line.strip()]
    if not stripped:
        return "No lsusb output available."
    return stripped[0]


def detect_wireless_inventory() -> WirelessInventoryReport:
    """Inspect USB adapters and wireless interfaces, then suggest the best iface."""
    lsusb_result = _run_command(["lsusb"], timeout=10)
    iw_dev_result = _run_command(["iw", "dev"], timeout=10)
    iwconfig_result = _run_command(["iwconfig"], timeout=10)

    iw_modes = _parse_iw_dev_interfaces(iw_dev_result.stdout)
    iwconfig_modes = _parse_iwconfig_interfaces(iwconfig_result.stdout)

    interface_names = sorted(
        set(iw_modes) | set(iwconfig_modes) | set(_list_sysfs_wireless_interfaces())
    )
    candidates: list[WirelessInterfaceCandidate] = []
    for name in interface_names:
        source_parts: list[str] = []
        if name in iw_modes:
            source_parts.append("iw")
        if name in iwconfig_modes:
            source_parts.append("iwconfig")
        if name in _list_sysfs_wireless_interfaces():
            source_parts.append("sysfs")
        mode = iw_modes.get(name) or iwconfig_modes.get(name) or "unknown"
        candidates.append(
            WirelessInterfaceCandidate(
                name=name,
                mode=mode,
                source="+".join(source_parts) or "unknown",
            )
        )

    preferred = choose_best_interface([candidate.name for candidate in candidates])
    if candidates:
        monitor_first = next(
            (candidate.name for candidate in candidates if "monitor" in candidate.mode),
            "",
        )
        preferred = monitor_first or preferred

    interface_summary = (
        ", ".join(f"{candidate.name}:{candidate.mode}" for candidate in candidates[:6])
        if candidates
        else "No wireless interfaces detected."
    )
    usb_summary = _summarize_usb_inventory(lsusb_result.stdout)
    summary = (
        f"Selected {preferred or '(none)'} | "
        f"USB {usb_summary} | Interfaces {interface_summary}"
    )
    return WirelessInventoryReport(
        interfaces=tuple(candidates),
        selected_interface=preferred,
        usb_summary=usb_summary,
        interface_summary=interface_summary,
        summary=summary,
    )


def _detect_interface_mode(interface: str) -> str:
    """Read the current mode for a specific interface."""
    normalized_interface = str(interface).strip()
    if not normalized_interface:
        return "unknown"

    info_result = _run_command(["iw", "dev", normalized_interface, "info"], timeout=10)
    if info_result.ok:
        for raw_line in info_result.stdout.splitlines():
            line = raw_line.strip().lower()
            if line.startswith("type "):
                return line.split(maxsplit=1)[1]

    iwconfig_result = _run_command(["iwconfig", normalized_interface], timeout=10)
    if iwconfig_result.ok:
        mode_match = re.search(r"Mode:([A-Za-z]+)", iwconfig_result.stdout)
        if mode_match is not None:
            return mode_match.group(1).strip().lower()

    return "unknown"


def _needs_sudo() -> bool:
    """Check if we need sudo for privileged network operations."""
    return os.getuid() != 0


def _privileged_command(args: list[str]) -> list[str]:
    """Prefix a command with sudo if not running as root."""
    if _needs_sudo():
        return ["sudo", *args]
    return args


def _unmanage_interface(interface: str, managed: bool = False) -> CommandResult:
    """Set NetworkManager management state for an interface."""
    if shutil.which("nmcli") is None:
        return CommandResult(ok=True, summary="nmcli not found, skipping.")

    state = "yes" if managed else "no"
    return _run_command(
        _privileged_command(["nmcli", "device", "set", interface, "managed", state]),
        timeout=10,
    )


def _unblock_interface(interface: str) -> CommandResult:
    """Ensure the interface is not soft-blocked by rfkill."""
    if shutil.which("rfkill") is None:
        return CommandResult(ok=True, summary="rfkill not found, skipping.")

    # Try to unblock wifi specifically or the interface name if possible
    return _run_command(
        _privileged_command(["rfkill", "unblock", "wifi"]),
        timeout=10,
    )


def set_interface_monitor_mode(
    interface: str,
    *,
    monitor: bool,
) -> CommandResult:
    """Switch a wireless interface between monitor and managed mode."""
    normalized_interface = str(interface).strip()
    if not normalized_interface:
        return CommandResult(ok=False, summary="Interface is required.", returncode=2)

    # 0. Pre-conditions: Ensure unblocked and unmanaged by NetworkManager
    _unblock_interface(normalized_interface)
    if monitor:
        # Only unmanage when going into monitor mode to avoid NM interference
        _unmanage_interface(normalized_interface, managed=False)

    desired_mode = "monitor" if monitor else "managed"
    down_result = _run_command(
        _privileged_command(["ip", "link", "set", normalized_interface, "down"]),
        timeout=15,
    )
    if not down_result.ok:
        hint = " (try running with sudo)" if _needs_sudo() else ""
        return CommandResult(
            ok=False,
            summary=f"Cannot bring down {normalized_interface}: {down_result.summary}{hint}",
            returncode=down_result.returncode,
            stdout=down_result.stdout,
            stderr=down_result.stderr,
        )

    switch_result = _run_command(
        _privileged_command(
            ["iw", "dev", normalized_interface, "set", "type", desired_mode]
        ),
        timeout=15,
    )
    if not switch_result.ok and shutil.which("iwconfig") is not None:
        switch_result = _run_command(
            _privileged_command(
                ["iwconfig", normalized_interface, "mode", desired_mode]
            ),
            timeout=15,
        )
    if not switch_result.ok:
        return CommandResult(
            ok=False,
            summary=f"Failed to switch {normalized_interface} to {desired_mode}: "
            f"{switch_result.summary}",
            returncode=switch_result.returncode,
            stdout=switch_result.stdout,
            stderr=switch_result.stderr,
        )

    up_result = _run_command(
        _privileged_command(["ip", "link", "set", normalized_interface, "up"]),
        timeout=15,
    )

    # Restore management if we just switched back to managed mode
    if not monitor:
        _unmanage_interface(normalized_interface, managed=True)

    if not up_result.ok:
        return CommandResult(
            ok=False,
            summary=f"Cannot bring up {normalized_interface}: {up_result.summary}",
            returncode=up_result.returncode,
            stdout=up_result.stdout,
            stderr=up_result.stderr,
        )

    current_mode = _detect_interface_mode(normalized_interface)
    mode_ok = current_mode == desired_mode or current_mode == "auto"
    return CommandResult(
        ok=mode_ok or current_mode == "unknown",
        summary=(
            f"{normalized_interface} is now {current_mode}."
            if current_mode != "unknown"
            else f"{normalized_interface} switched to {desired_mode}."
        ),
        stdout="\n".join(
            chunk
            for chunk in (down_result.stdout, switch_result.stdout, up_result.stdout)
            if chunk
        ),
        stderr="\n".join(
            chunk
            for chunk in (down_result.stderr, switch_result.stderr, up_result.stderr)
            if chunk
        ),
        returncode=0 if mode_ok else up_result.returncode,
    )


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
