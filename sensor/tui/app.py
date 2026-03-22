"""
Sentinel NetLab TUI - Main Application
Entry point: python -m sensor.tui

Operational Framework:
  Screen 1 (Setup): Mode select, auto-detect WiFi, pre-flight validation.
  Screen 2 (Dashboard): 4-panel real-time with alert debouncing & graceful shutdown.
"""

import glob
import logging
import os
import queue
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    RichLog,
    Select,
)

from sensor.config import Config, init_config
from sensor.sensor_controller import SensorController
from sensor.tui.bootstrap import EnvLoadResult, load_tui_env
from sensor.tui.config_store import (
    BUILTIN_TUI_PRESETS,
    apply_tui_preset,
    coerce_sensor_id,
    delete_tui_profile,
    list_saved_tui_profiles,
    load_raw_config,
    load_saved_tui_settings,
    load_tui_profile,
    normalize_tui_settings,
    parse_channel_list,
    parse_geo_coordinate,
    persist_tui_settings,
    resolve_config_path,
    save_tui_profile,
    validate_tui_settings,
)
from sensor.tui.setup_wizard import (
    DEFAULT_PROD_HEALTH_URL,
    AuditRunReport,
    BackendCheckReport,
    CommandResult,
    DeploymentActionReport,
    LabActionReport,
    WirelessInventoryReport,
    build_bootstrap_env,
    build_pytest_command,
    build_quick_profile,
    build_sensor_daemon_command,
    build_upload_url,
    collect_backend_health,
    detect_wireless_inventory,
    install_python_component,
    normalize_controller_url,
    normalize_health_url,
    open_dashboard_gui,
    probe_health_endpoint,
    request_sensor_token,
    resolve_test_targets,
    run_lab_action,
    run_prod_action,
    run_security_audit,
    run_tests,
    set_interface_monitor_mode,
    upsert_env_file,
)
from sensor.tui.state_manager import (
    AlertEntry,
    AppState,
    NetworkEntry,
    TUILogHandler,
)
from sensor.tui.wardrive_store import (
    WardriveSnapshot,
    load_wardrive_snapshot,
    resolve_wardrive_session_path,
)

# ─── Constants ───────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
REFRESH_INTERVAL = 0.8  # seconds


# ─── Helpers ─────────────────────────────────────────────────────────────────
def detect_wifi_interfaces() -> list[str]:
    """Auto-detect available wireless interfaces on Linux."""
    interfaces = []
    try:
        wireless_path = "/sys/class/net"
        if os.path.isdir(wireless_path):
            for iface in os.listdir(wireless_path):
                phy_path = os.path.join(wireless_path, iface, "wireless")
                phy80211 = os.path.join(wireless_path, iface, "phy80211")
                if os.path.isdir(phy_path) or os.path.isdir(phy80211):
                    interfaces.append(iface)
        # Also check for monitor mode interfaces
        for iface_dir in glob.glob("/sys/class/net/*mon*"):
            name = os.path.basename(iface_dir)
            if name not in interfaces:
                interfaces.append(name)
    except Exception:  # noqa: S110
        pass
    return interfaces or ["(none detected)"]


def check_controller_online(base_url: str | None = None) -> bool:
    """Quick check if the Controller API is reachable."""
    try:
        import urllib.request

        url = normalize_controller_url(base_url or os.environ.get("CONTROLLER_URL"))
        if not url.startswith(("http://", "https://")):
            return False
        # Try multiple health paths (lab/prod may differ)
        for path in ("/api/v1/health", "/health", "/"):
            try:
                resp = urllib.request.urlopen(  # noqa: S310 # nosec B310
                    f"{url}{path}", timeout=2
                )
                if resp.getcode() == 200:
                    return True
            except Exception:  # noqa: S110, S112
                continue
        return False
    except Exception:  # noqa: S110
        return False


def _format_event_time(raw_value: Any) -> str:
    """Render timestamps consistently for the TUI widgets."""
    if isinstance(raw_value, datetime):
        return raw_value.strftime("%H:%M:%S")

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return datetime.now().strftime("%H:%M:%S")
        try:
            normalized = text.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).strftime("%H:%M:%S")
        except ValueError:
            return text[-8:] if len(text) >= 8 else text

    return datetime.now().strftime("%H:%M:%S")


class SetupScroll(VerticalScroll):
    """Scrollable setup form that keeps focus on actionable widgets."""

    can_focus = False


# ═══════════════════════════════════════════════════════════════════════════════
# MODAL: GRACEFUL SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════════════
class ShutdownModal(ModalScreen):
    """Modal overlay shown during graceful shutdown."""

    DEFAULT_CSS = """
    ShutdownModal {
        align: center middle;
    }
    #shutdown-box {
        width: 50;
        height: 12;
        border: heavy #f85149;
        background: #161b22;
        padding: 2 4;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="shutdown-box"):
            yield Label("[b red]⏻  SHUTTING DOWN[/b red]", id="sd-title")
            yield Label("", id="sd-status")
            yield Label("")
            yield Label("[dim]Sẽ tự động thoát sau khi hoàn tất…[/dim]")

    def on_mount(self) -> None:
        self.run_shutdown_sequence()

    def run_shutdown_sequence(self) -> None:
        """Animate the shutdown steps."""
        self.set_timer(0.3, lambda: self._update("🔄 Đang dừng Sensor Worker…"))
        self.set_timer(1.0, lambda: self._update("📦 Đang xả hàng đợi Spool…"))
        self.set_timer(1.8, lambda: self._update("💾 Đang lưu trạng thái…"))
        self.set_timer(2.5, lambda: self._update("📡 Đóng card mạng…"))
        self.set_timer(3.2, self._finish)

    def _update(self, msg: str) -> None:
        try:
            self.query_one("#sd-status", Label).update(msg)
        except Exception:  # noqa: S110
            pass  # noqa: S110

    def _finish(self) -> None:
        app = self.app
        if isinstance(app, SentinelTUIApp) and not app.is_shutdown_complete():
            self._update("⏳ Đang chờ Sensor dừng an toàn…")
            self.set_timer(0.5, self._finish)
            return
        app.exit()


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 1: SETUP & CONFIG (Pre-flight Check)
# ═══════════════════════════════════════════════════════════════════════════════
class SetupScreen(Screen):
    """Configuration screen with auto-detection and pre-flight validation."""

    BINDINGS = [Binding("f5", "start_sensor", "Start Sensor")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="setup-screen"):
            with SetupScroll(id="setup-container"):
                yield Label(
                    "[bold cyan]Sentinel NetLab[/bold cyan]",
                    classes="panel-title",
                )
                yield Label(
                    "[dim]Quick sensor bootstrap for demo, replay, and live capture.[/dim]",
                    classes="setup-subtitle",
                )

                # Pre-flight status
                with Container(classes="setup-group"):
                    yield Label("🔍 PRE-FLIGHT CHECK", classes="setup-group-title")
                    yield Label("", id="pf-env")
                    yield Label("", id="pf-wifi")
                    yield Label("", id="pf-controller")

                with Container(classes="setup-group"):
                    yield Label("🚀 QUICK SETUP", classes="setup-group-title")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Demo Bundle", id="btn-quick-demo")
                        yield Button("Live Bundle", id="btn-quick-live")
                        yield Button("Gen .env Keys", id="btn-gen-secrets")
                    with Horizontal(classes="setup-row", id="row-controller-url"):
                        yield Label("Controller URL", classes="setup-label")
                        yield Input(
                            value="http://127.0.0.1:8080",
                            placeholder="http://127.0.0.1:8080",
                            id="input-controller-url",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-admin-token"):
                        yield Label("Admin Token", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="Optional, used to auto-create sensor token",
                            password=True,
                            id="input-admin-token",
                            classes="setup-input",
                        )
                    yield Label("", id="quick-setup-status")

                with Container(classes="setup-group"):
                    yield Label("🗂️ PROFILES & PRESETS", classes="setup-group-title")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Balanced Live", id="btn-preset-balanced-live")
                        yield Button("SOC Tactical", id="btn-preset-soc-tactical")
                        yield Button("PCAP Forensics", id="btn-preset-pcap-forensics")
                    with Horizontal(classes="setup-row", id="row-profile-select"):
                        yield Label("Saved Profiles", classes="setup-label")
                        yield Select(
                            [("(no saved profiles)", "")],
                            value="",
                            id="select-profile",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-profile-name"):
                        yield Label("Profile Name", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="soc-lab, replay-case-01, field-team-a",
                            id="input-profile-name",
                            classes="setup-input",
                        )
                    with Horizontal(classes="quick-actions"):
                        yield Button("Save Profile", id="btn-save-profile")
                        yield Button("Load Selected", id="btn-load-profile")
                        yield Button("Delete Selected", id="btn-delete-profile")
                    yield Label("", id="preset-summary")
                    yield Label("", id="profile-status")
                    yield Label("", id="profile-inventory", classes="setup-hint")

                # Core configuration
                with Container(classes="setup-group"):
                    yield Label("🔌 CONFIGURATION", classes="setup-group-title")
                    with Horizontal(classes="setup-row", id="row-sensor-id"):
                        yield Label("Sensor ID", classes="setup-label")
                        yield Input(
                            value="tui-sensor-01",
                            placeholder="Unique sensor identifier",
                            id="input-sensor-id",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-interface"):
                        yield Label("Interface", classes="setup-label")
                        yield Select(
                            [("(none detected)", "(none detected)")],
                            value="(none detected)",
                            id="select-iface",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-iface-custom"):
                        yield Label("Custom Iface", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="Manual override (e.g. wlan1mon)",
                            id="input-iface",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-pcap"):
                        yield Label("PCAP Path", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="/path/to/capture.pcap",
                            id="input-pcap",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-pcap-opts"):
                        yield Label("PCAP Options", classes="setup-label")
                        yield Checkbox("Loop Replay", id="chk-pcap-loop", value=True)
                        yield Checkbox("Realtime", id="chk-pcap-realtime", value=True)
                    with Horizontal(classes="setup-row", id="row-geo-x"):
                        yield Label("Geo Sensor X", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="e.g. 12.5",
                            id="input-geo-x",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-geo-y"):
                        yield Label("Geo Sensor Y", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="e.g. 4.0",
                            id="input-geo-y",
                            classes="setup-input",
                        )

                # Mode Selection
                with Container(classes="setup-group"):
                    yield Label("⚡ OPERATION MODE", classes="setup-group-title")
                    with RadioSet(id="mode-select"):
                        yield RadioButton(
                            "(A) Live Combat — Thực chiến", id="mode-live"
                        )
                        yield RadioButton(
                            "(B) Mock / Test Lab", id="mode-mock", value=True
                        )
                        yield RadioButton(
                            "(C) PCAP Replay — Phân tích lại", id="mode-pcap"
                        )

                # Toggles
                with Container(classes="setup-group"):
                    yield Label("🧠 FEATURES", classes="setup-group-title")
                    with Horizontal(classes="setup-row", id="row-det-profile"):
                        yield Label("Detector Profile", classes="setup-label")
                        yield Select(
                            [
                                ("Lite Realtime (Fast)", "lite_realtime"),
                                ("Full WIDS (Heavy)", "full_wids"),
                                ("Audit/Offline Replay", "audit_offline"),
                            ],
                            value="lite_realtime",
                            id="select-det-profile",
                            classes="setup-input",
                        )
                    yield Checkbox("Enable ML Boost", id="chk-ml", value=False)
                    yield Checkbox("Enable Geo-Location", id="chk-geo", value=False)
                    yield Checkbox(
                        "Anonymize MAC/SSID (Quyền riêng tư)", id="chk-anon", value=True
                    )

                with Container(classes="setup-group"):
                    yield Label("📡 INTERFACE AUTOMATION", classes="setup-group-title")
                    is_root = os.getuid() == 0
                    if not is_root:
                        yield Label(
                            "[bold red]⚠ NOT RUNNING AS ROOT[/bold red]\n"
                            "[dim]Interface automation requires sudo without password or running with sudo python -m sensor.tui[/dim]",
                            classes="setup-hint",
                            id="root-warning",
                        )
                    else:
                        yield Label(
                            "[green]✓ Running with root privileges[/green]",
                            classes="setup-hint",
                        )
                    with Horizontal(classes="quick-actions"):
                        yield Button("Detect USB/IW", id="btn-detect-iface")
                        yield Button("Monitor Mode", id="btn-monitor-on")
                        yield Button("Managed Mode", id="btn-monitor-off")
                    yield Label("", id="iface-status")
                    yield Label("", id="iface-summary", classes="setup-hint")

                with Container(classes="setup-group"):
                    yield Label("⚙️ BACKEND & LAB", classes="setup-group-title")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Check Stack", id="btn-check-stack")
                        yield Button("Install Sensor", id="btn-install-sensor")
                        yield Button("Install Controller", id="btn-install-controller")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Install Engine", id="btn-install-engine")
                        yield Button("Lab Up", id="btn-lab-up")
                        yield Button("Lab Down", id="btn-lab-down")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Lab Reset", id="btn-lab-reset")
                        yield Button("Lab Status", id="btn-lab-status")
                        yield Button("Gen Docker Tokens", id="btn-lab-gen")
                    with Horizontal(classes="quick-actions"):
                        yield Button("Run Tests", id="btn-run-tests")
                        yield Button("Open GUI", id="btn-open-gui")
                    yield Label("", id="backend-status")
                    yield Label("", id="lab-status")
                    yield Label("", id="lab-autofill", classes="setup-hint")

                with Container(classes="setup-group"):
                    yield Label("🔎 SECURITY AUDIT", classes="setup-group-title")
                    with Horizontal(classes="setup-row", id="row-audit-profile"):
                        yield Label("Audit Profile", classes="setup-label")
                        yield Input(
                            value="home",
                            placeholder="home, sme, enterprise",
                            id="input-audit-profile",
                            classes="setup-input",
                        )
                    with Horizontal(classes="setup-row", id="row-audit-output"):
                        yield Label("Audit Output", classes="setup-label")
                        yield Input(
                            value="artifacts/audit_report.json",
                            placeholder="artifacts/audit_report.json",
                            id="input-audit-output",
                            classes="setup-input",
                        )
                    yield Checkbox(
                        "Use Mock Discovery", id="chk-audit-mock", value=True
                    )
                    with Horizontal(classes="quick-actions"):
                        yield Button("Run Security Audit", id="btn-run-audit")
                        yield Button("Clear Audit", id="btn-clear-audit")
                    yield Label("", id="audit-status")
                    yield Label("", id="audit-summary", classes="setup-hint")
                    audit_table: DataTable = DataTable(id="audit-results")
                    audit_table.cursor_type = "row"
                    audit_table.zebra_stripes = True
                    yield audit_table
                    yield RichLog(
                        id="audit-log",
                        max_lines=120,
                        highlight=True,
                        markup=True,
                    )

                with Container(classes="setup-group"):
                    yield Label("🧪 DIAGNOSTICS", classes="setup-group-title")
                    yield Checkbox("Unit Tests", id="chk-tests-unit", value=True)
                    yield Checkbox(
                        "Integration Tests",
                        id="chk-tests-integration",
                        value=True,
                    )
                    yield Checkbox("All Tests", id="chk-tests-all", value=False)
                    with Horizontal(classes="quick-actions"):
                        yield Button(
                            "Run Diagnostics / Tests", id="btn-run-tests-stream"
                        )
                        yield Button("Clear Diagnostics", id="btn-clear-tests")
                    yield Label("", id="diag-status")
                    yield RichLog(
                        id="diag-log",
                        max_lines=160,
                        highlight=True,
                        markup=False,
                    )

                with Container(classes="setup-group"):
                    yield Label(
                        "🏭 OPERATIONS & DEPLOYMENT",
                        classes="setup-group-title",
                    )
                    with Horizontal(classes="quick-actions"):
                        yield Button(
                            "Start Background Daemon",
                            id="btn-start-daemon",
                        )
                        yield Button(
                            "Stop Background Daemon",
                            id="btn-stop-daemon",
                        )
                    yield Label("", id="daemon-status")
                    yield Label("", id="daemon-details", classes="setup-hint")
                    with Horizontal(classes="setup-row", id="row-prod-health-url"):
                        yield Label("Prod Health URL", classes="setup-label")
                        yield Input(
                            value=DEFAULT_PROD_HEALTH_URL,
                            placeholder="http://127.0.0.1/health",
                            id="input-prod-health-url",
                            classes="setup-input",
                        )
                    with Horizontal(classes="quick-actions"):
                        yield Button(
                            "Deploy Production Controller",
                            id="btn-prod-up",
                        )
                        yield Button("Stop Prod Stack", id="btn-prod-down")
                        yield Button("Prod Status", id="btn-prod-status")
                    yield Label("", id="prod-status")
                    yield Label("", id="prod-health", classes="setup-hint")
                    yield Label("", id="prod-details", classes="setup-hint")

                # Validation error area
                yield Label("", id="validation-error")

                yield Button(
                    "▶  START SENSOR  (F5)",
                    id="btn-start",
                    variant="success",
                )

        yield Footer()

    def on_mount(self) -> None:
        """Auto-detect environment on screen load."""
        app = self._sentinel_app()
        self._audit_running = False
        self._diagnostics_running = False
        defaults = normalize_tui_settings(app.saved_settings)
        self._advanced_settings = self._extract_advanced_settings(defaults)
        self._available_ifaces = detect_wifi_interfaces()
        sensor_id = coerce_sensor_id(
            defaults.get("sensor_id"),
            os.environ.get("SENSOR_ID", "tui-sensor-01"),
        )

        # Auto-fill best interface
        self._populate_iface_select(self._available_ifaces)
        if defaults.get("interface"):
            saved_iface = str(defaults["interface"])
            self.query_one("#input-iface", Input).value = saved_iface
            try:
                self.query_one("#select-iface", Select).value = saved_iface
            except Exception:  # noqa: S110
                pass
        elif self._available_ifaces[0] != "(none detected)":
            best = next(
                (i for i in self._available_ifaces if "mon" in i),
                self._available_ifaces[0],
            )
            try:
                self.query_one("#select-iface", Select).value = best
            except Exception:  # noqa: S110
                pass

        self.query_one("#input-sensor-id", Input).value = sensor_id
        self.query_one("#input-pcap", Input).value = str(defaults.get("pcap_path", ""))
        self.query_one("#input-controller-url", Input).value = str(
            defaults.get("controller_url")
            or os.environ.get("CONTROLLER_URL")
            or "http://127.0.0.1:8080"
        )
        self.query_one("#input-admin-token", Input).value = str(
            os.environ.get("SENTINEL_ADMIN_TOKEN", "")
        )
        self.query_one("#input-profile-name", Input).value = str(
            defaults.get("profile_name", "")
        )
        self.query_one("#input-geo-x", Input).value = str(
            defaults.get("geo_sensor_x_m", "")
        )
        self.query_one("#input-geo-y", Input).value = str(
            defaults.get("geo_sensor_y_m", "")
        )
        self.query_one("#input-audit-profile", Input).value = str(
            defaults.get("audit_profile", "home")
        )
        self.query_one("#input-audit-output", Input).value = str(
            defaults.get("audit_output", "artifacts/audit_report.json")
        )
        self.query_one("#input-prod-health-url", Input).value = str(
            defaults.get("prod_health_url", DEFAULT_PROD_HEALTH_URL)
        )
        self.query_one("#chk-ml", Checkbox).value = bool(defaults.get("ml_enabled"))
        self.query_one("#chk-geo", Checkbox).value = bool(defaults.get("geo_enabled"))
        self.query_one("#chk-anon", Checkbox).value = bool(
            defaults.get("anonymize", True)
        )
        self.query_one("#chk-audit-mock", Checkbox).value = bool(
            defaults.get("audit_use_mock", defaults.get("mode", "mock") != "live")
        )

        mode = defaults.get("mode", "mock")
        mode_map = {"live": "#mode-live", "pcap": "#mode-pcap", "mock": "#mode-mock"}
        target_id = mode_map.get(mode, "#mode-mock")
        self.query_one(target_id, RadioButton).value = True

        audit_table = self.query_one("#audit-results", DataTable)
        audit_table.add_columns("Severity", "Title", "Status", "Evidence", "Action")

        self._sync_dynamic_rows()
        self._refresh_preflight()
        self._refresh_profile_inventory()
        self._refresh_profile_summary(defaults)
        self._refresh_runtime_operations()
        self.set_interval(4.0, self._refresh_runtime_operations)
        self.call_after_refresh(lambda: self.set_focus(None))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.set_focus(None)
        if event.button.id == "btn-start":
            self.action_start_sensor()
        elif event.button.id == "btn-quick-demo":
            self._apply_quick_bundle("demo")
        elif event.button.id == "btn-quick-live":
            self._apply_quick_bundle("live")
        elif event.button.id == "btn-gen-secrets":
            self._generate_token_and_keys()
        elif event.button.id == "btn-preset-balanced-live":
            self._apply_config_preset("balanced_live")
        elif event.button.id == "btn-preset-soc-tactical":
            self._apply_config_preset("soc_tactical")
        elif event.button.id == "btn-preset-pcap-forensics":
            self._apply_config_preset("pcap_forensics")
        elif event.button.id == "btn-save-profile":
            self._save_named_profile()
        elif event.button.id == "btn-load-profile":
            self._load_named_profile()
        elif event.button.id == "btn-delete-profile":
            self._delete_named_profile()
        elif event.button.id == "btn-check-stack":
            controller_url = self._controller_url()
            self._run_setup_task(
                "#backend-status",
                "Checking backend stack…",
                lambda: collect_backend_health(controller_url),
                self._handle_backend_check,
            )
        elif event.button.id == "btn-install-sensor":
            self._run_setup_task(
                "#backend-status",
                "Installing sensor dependencies…",
                lambda: install_python_component(PROJECT_ROOT, "sensor"),
                lambda result: self._handle_install_result("Sensor", result),
            )
        elif event.button.id == "btn-install-controller":
            self._run_setup_task(
                "#backend-status",
                "Installing controller dependencies…",
                lambda: install_python_component(PROJECT_ROOT, "controller"),
                lambda result: self._handle_install_result("Controller", result),
            )
        elif event.button.id == "btn-install-engine":
            self._run_setup_task(
                "#backend-status",
                "Installing engine/dashboard dependencies…",
                lambda: install_python_component(PROJECT_ROOT, "engine"),
                lambda result: self._handle_install_result("Engine", result),
            )
        elif event.button.id == "btn-lab-up":
            sensor_id = self.query_one("#input-sensor-id", Input).value
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Starting lab stack…",
                lambda: run_lab_action(
                    PROJECT_ROOT,
                    "up",
                    sensor_id=sensor_id,
                    controller_url=controller_url,
                ),
                self._handle_lab_action,
            )
        elif event.button.id == "btn-lab-down":
            sensor_id = self.query_one("#input-sensor-id", Input).value
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Stopping lab stack…",
                lambda: run_lab_action(
                    PROJECT_ROOT,
                    "down",
                    sensor_id=sensor_id,
                    controller_url=controller_url,
                ),
                self._handle_lab_action,
            )
        elif event.button.id == "btn-lab-reset":
            sensor_id = self.query_one("#input-sensor-id", Input).value
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Resetting lab stack…",
                lambda: run_lab_action(
                    PROJECT_ROOT,
                    "reset",
                    sensor_id=sensor_id,
                    controller_url=controller_url,
                ),
                self._handle_lab_action,
            )
        elif event.button.id == "btn-lab-status":
            sensor_id = self.query_one("#input-sensor-id", Input).value
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Checking lab status…",
                lambda: run_lab_action(
                    PROJECT_ROOT,
                    "status",
                    sensor_id=sensor_id,
                    controller_url=controller_url,
                ),
                self._handle_lab_action,
            )
        elif event.button.id == "btn-lab-gen":
            sensor_id = self.query_one("#input-sensor-id", Input).value
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Generating lab runtime tokens…",
                lambda: run_lab_action(
                    PROJECT_ROOT,
                    "generate_tokens",
                    sensor_id=sensor_id,
                    controller_url=controller_url,
                ),
                self._handle_lab_action,
            )
        elif event.button.id == "btn-run-tests":
            self._run_setup_task(
                "#backend-status",
                "Running pytest suite…",
                lambda: run_tests(PROJECT_ROOT),
                self._handle_test_result,
            )
        elif event.button.id == "btn-run-audit":
            self._launch_security_audit()
        elif event.button.id == "btn-clear-audit":
            self._clear_audit_results()
        elif event.button.id == "btn-run-tests-stream":
            self._launch_diagnostics_run()
        elif event.button.id == "btn-clear-tests":
            self._clear_diagnostics()
        elif event.button.id == "btn-start-daemon":
            self._start_background_daemon()
        elif event.button.id == "btn-stop-daemon":
            self._stop_background_daemon()
        elif event.button.id == "btn-prod-up":
            self._run_setup_task(
                "#prod-status",
                "Deploying production compose stack…",
                lambda: run_prod_action(
                    PROJECT_ROOT,
                    "up",
                    health_url=self._prod_health_url(),
                ),
                self._handle_prod_action,
            )
        elif event.button.id == "btn-prod-down":
            self._run_setup_task(
                "#prod-status",
                "Stopping production compose stack…",
                lambda: run_prod_action(
                    PROJECT_ROOT,
                    "down",
                    health_url=self._prod_health_url(),
                ),
                self._handle_prod_action,
            )
        elif event.button.id == "btn-prod-status":
            self._run_setup_task(
                "#prod-status",
                "Checking production compose stack…",
                lambda: run_prod_action(
                    PROJECT_ROOT,
                    "status",
                    health_url=self._prod_health_url(),
                ),
                self._handle_prod_action,
            )
        elif event.button.id == "btn-open-gui":
            controller_url = self._controller_url()
            self._run_setup_task(
                "#lab-status",
                "Opening dashboard GUI…",
                lambda: open_dashboard_gui(controller_url),
                self._handle_gui_launch,
            )
        elif event.button.id == "btn-detect-iface":
            self._run_setup_task(
                "#iface-status",
                "Scanning USB and wireless interfaces…",
                detect_wireless_inventory,
                self._handle_interface_inventory,
            )
        elif event.button.id == "btn-monitor-on":
            interface = self._selected_iface()
            self._run_setup_task(
                "#iface-status",
                "Switching interface to monitor mode…",
                lambda: set_interface_monitor_mode(interface, monitor=True),
                lambda result: self._handle_interface_mode_change(
                    "Monitor mode",
                    result,
                ),
            )
        elif event.button.id == "btn-monitor-off":
            interface = self._selected_iface()
            self._run_setup_task(
                "#iface-status",
                "Restoring interface to managed mode…",
                lambda: set_interface_monitor_mode(interface, monitor=False),
                lambda result: self._handle_interface_mode_change(
                    "Managed mode",
                    result,
                ),
            )

    def _handle_test_result(self, result: CommandResult) -> None:
        """Render the pytest outcome to the backend status area."""
        color = "green" if result.ok else "red"
        status = f"[{color}]TESTS: {result.summary}[/{color}]"
        self.query_one("#backend-status", Label).update(status)
        app = self._sentinel_app()
        if not result.ok:
            app.app_state.push_log(
                f"[Error] Pytest failed:\n{result.stderr or result.stdout}"
            )
        else:
            app.app_state.push_log("[System] All tests passed.")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk-geo":
            self._sync_dynamic_rows()
        elif event.checkbox.id == "chk-tests-all" and event.checkbox.value:
            self.query_one("#chk-tests-unit", Checkbox).value = False
            self.query_one("#chk-tests-integration", Checkbox).value = False
        elif event.checkbox.id in {"chk-tests-unit", "chk-tests-integration"}:
            if event.checkbox.value:
                self.query_one("#chk-tests-all", Checkbox).value = False

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "select-profile":
            selected = event.value
            if selected and selected != Select.BLANK:
                self.query_one("#input-profile-name", Input).value = str(selected)
                self._load_named_profile()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode-select":
            self._sync_dynamic_rows()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "input-pcap":
            self._sync_dynamic_rows()

    def _refresh_preflight(self) -> None:
        app = self._sentinel_app()

        env_color = "green" if app.env_load_result.loaded else "yellow"
        if app.env_load_result.loaded and app.env_load_result.path is not None:
            env_text = app.env_load_result.path.name
        elif app.env_load_result.path is not None:
            env_text = f"{app.env_load_result.path.name} ({app.env_load_result.status})"
        else:
            env_text = app.env_load_result.status
        self.query_one("#pf-env", Label).update(
            f"Env: [{env_color}]{env_text}[/{env_color}]"
        )

        iface_text = ", ".join(self._available_ifaces)
        has_wifi = self._available_ifaces[0] != "(none detected)"
        color = "green" if has_wifi else "yellow"
        self.query_one("#pf-wifi", Label).update(
            f"WiFi Cards: [{color}]{iface_text}[/{color}]"
        )

        ctrl_ok = check_controller_online(self._controller_url())
        ctrl_color = "green" if ctrl_ok else "red"
        ctrl_text = "ONLINE ✓" if ctrl_ok else "OFFLINE ✗ (check controller URL)"
        self.query_one("#pf-controller", Label).update(
            f"Controller: [{ctrl_color}]{ctrl_text}[/{ctrl_color}]"
        )

    def _sync_dynamic_rows(self) -> None:
        mode = self._selected_mode()
        geo_enabled = self.query_one("#chk-geo", Checkbox).value
        pcap_row = self.query_one("#row-pcap", Horizontal)
        pcap_opts_row = self.query_one("#row-pcap-opts", Horizontal)
        pcap_row.display = mode == "pcap"
        pcap_opts_row.display = mode == "pcap"
        if mode == "pcap":
            pcap_label = pcap_row.query_one(".setup-label", Label)
            pcap_val = self.query_one("#input-pcap", Input).value.strip()
            if not pcap_val:
                pcap_label.update("PCAP Path [b red]*[/b red]")
            else:
                pcap_label.update("PCAP Path [green]✓[/green]")

        self.query_one("#row-geo-x", Horizontal).display = geo_enabled
        self.query_one("#row-geo-y", Horizontal).display = geo_enabled

    def _selected_mode(self) -> str:
        if self.query_one("#mode-live", RadioButton).value:
            return "live"
        if self.query_one("#mode-pcap", RadioButton).value:
            return "pcap"
        return "mock"

    def _selected_iface(self) -> str:
        """Return the active interface from custom Input or Select dropdown."""
        custom = self.query_one("#input-iface", Input).value.strip()
        if custom:
            return custom
        try:
            selected = self.query_one("#select-iface", Select).value
            if selected and selected != Select.BLANK and selected != "(none detected)":
                return str(selected)
        except Exception:  # noqa: S110
            pass
        return "wlan0mon"

    def _populate_iface_select(self, interfaces: list[str]) -> None:
        """Refresh the interface Select dropdown with detected interfaces."""
        select_widget = self.query_one("#select-iface", Select)
        if not interfaces or interfaces == ["(none detected)"]:
            select_widget.set_options([("(none detected)", "(none detected)")])
            select_widget.value = "(none detected)"
            return
        options = [(iface, iface) for iface in interfaces]
        select_widget.set_options(options)
        # Prefer monitor mode interface
        best = next((i for i in interfaces if "mon" in i), interfaces[0])
        select_widget.value = best

    def _controller_url(self) -> str:
        return normalize_controller_url(
            self.query_one("#input-controller-url", Input).value
        )

    def _collect_settings(self) -> dict[str, Any]:
        settings = normalize_tui_settings(self._advanced_settings)
        app = self._sentinel_app()
        mode = self._selected_mode()
        iface = self._selected_iface()
        pcap_path = self.query_one("#input-pcap", Input).value
        sensor_id = coerce_sensor_id(
            self.query_one("#input-sensor-id", Input).value,
            os.environ.get("SENSOR_ID")
            or app.saved_settings.get("sensor_id")
            or "tui-sensor-01",
        )
        settings.update(
            {
                "mode": mode,
                "sensor_id": sensor_id,
                "interface": iface,
                "pcap_path": pcap_path,
                "controller_url": self._controller_url(),
                "ml_enabled": self.query_one("#chk-ml", Checkbox).value,
                "geo_enabled": self.query_one("#chk-geo", Checkbox).value,
                "geo_sensor_x_m": self.query_one("#input-geo-x", Input).value.strip(),
                "geo_sensor_y_m": self.query_one("#input-geo-y", Input).value.strip(),
                "anonymize": self.query_one("#chk-anon", Checkbox).value,
                "det_profile": self.query_one("#select-det-profile", Select).value,
                "pcap_loop": self.query_one("#chk-pcap-loop", Checkbox).value,
                "pcap_realtime": self.query_one("#chk-pcap-realtime", Checkbox).value,
                "profile_name": self.query_one("#input-profile-name", Input).value,
                "audit_profile": self.query_one("#input-audit-profile", Input).value,
                "audit_output": self.query_one("#input-audit-output", Input).value,
                "audit_use_mock": self.query_one("#chk-audit-mock", Checkbox).value,
                "prod_health_url": self._prod_health_url(),
            }
        )
        return normalize_tui_settings(settings)

    def _persist_setup_state(
        self,
        tui_settings: dict[str, Any],
        *,
        status_message: str | None = None,
    ) -> None:
        app = self._sentinel_app()
        app.tui_config = tui_settings
        app.config_path = persist_tui_settings(
            PROJECT_ROOT, app.config_path, app.tui_config
        )
        app.saved_settings = load_saved_tui_settings(app.config_path)
        self._advanced_settings = self._extract_advanced_settings(app.saved_settings)
        app.app_state.push_log(f"[System] Saved config to {app.config_path.name}")
        self._refresh_profile_summary(app.saved_settings)
        if status_message:
            self.query_one("#quick-setup-status", Label).update(status_message)

    def _apply_settings_to_inputs(self, settings: dict[str, Any]) -> None:
        scroll_container = self.query_one("#setup-container", SetupScroll)
        current_scroll_x = scroll_container.scroll_x
        current_scroll_y = scroll_container.scroll_y
        merged = normalize_tui_settings({**self._advanced_settings, **settings})
        self._advanced_settings = self._extract_advanced_settings(merged)

        self.query_one("#input-sensor-id", Input).value = str(merged["sensor_id"])
        self.query_one("#input-iface", Input).value = str(merged["interface"])
        try:
            self.query_one("#select-iface", Select).value = str(merged["interface"])
        except Exception:  # noqa: S110
            pass
        self.query_one("#input-pcap", Input).value = str(merged["pcap_path"])
        self.query_one("#input-controller-url", Input).value = str(
            merged["controller_url"]
        )
        self.query_one("#input-admin-token", Input).value = str(
            merged.get("admin_token", "")
        )
        self.query_one("#input-profile-name", Input).value = str(
            merged.get("profile_name", "")
        )
        self.query_one("#input-geo-x", Input).value = str(merged["geo_sensor_x_m"])
        self.query_one("#input-geo-y", Input).value = str(merged["geo_sensor_y_m"])
        self.query_one("#chk-ml", Checkbox).value = bool(merged["ml_enabled"])
        self.query_one("#chk-geo", Checkbox).value = bool(merged["geo_enabled"])
        self.query_one("#chk-anon", Checkbox).value = bool(merged["anonymize"])
        self.query_one("#select-det-profile", Select).value = str(
            merged.get("det_profile", "lite_realtime")
        )
        self.query_one("#chk-pcap-loop", Checkbox).value = bool(
            merged.get("pcap_loop", True)
        )
        self.query_one("#chk-pcap-realtime", Checkbox).value = bool(
            merged.get("pcap_realtime", True)
        )
        self.query_one("#input-audit-profile", Input).value = str(
            merged.get("audit_profile", "home")
        )
        self.query_one("#input-audit-output", Input).value = str(
            merged.get("audit_output", "artifacts/audit_report.json")
        )
        self.query_one("#chk-audit-mock", Checkbox).value = bool(
            merged.get("audit_use_mock", merged["mode"] != "live")
        )
        self.query_one("#input-prod-health-url", Input).value = str(
            merged.get("prod_health_url", DEFAULT_PROD_HEALTH_URL)
        )
        mode_map = {"live": "#mode-live", "pcap": "#mode-pcap", "mock": "#mode-mock"}
        target_id = mode_map.get(merged["mode"], "#mode-mock")
        self.query_one(target_id, RadioButton).value = True
        self._sync_dynamic_rows()
        self._refresh_profile_summary(merged)
        self.call_after_refresh(
            lambda: self.call_later(
                lambda: scroll_container.scroll_to(
                    x=current_scroll_x,
                    y=current_scroll_y,
                    animate=False,
                    force=True,
                    immediate=True,
                )
            )
        )

    def _write_runtime_env(
        self,
        profile: str,
        sensor_id: str,
        *,
        sensor_token: str | None = None,
    ) -> Path:
        admin_token = self.query_one("#input-admin-token", Input).value.strip()
        env_updates = build_bootstrap_env(
            profile,
            sensor_id,
            self._controller_url(),
            os.environ,
            sensor_token=sensor_token,
            admin_token=admin_token,
        )
        env_path = upsert_env_file(PROJECT_ROOT / ".env", env_updates)
        os.environ.update(env_updates)
        app = self._sentinel_app()
        app.env_load_result = EnvLoadResult(
            loaded=True,
            path=env_path,
            status=f"Updated {env_path.name}",
        )
        return env_path

    def _apply_quick_bundle(self, profile: str) -> None:
        current_sensor_id = self.query_one("#input-sensor-id", Input).value
        controller_url = self.query_one("#input-controller-url", Input).value
        settings = build_quick_profile(
            profile,
            available_ifaces=self._available_ifaces,
            current_sensor_id=current_sensor_id,
            controller_url=controller_url,
        )
        self._apply_settings_to_inputs(settings)
        env_path = self._write_runtime_env(profile, str(settings["sensor_id"]))
        self._persist_setup_state(
            self._collect_settings(),
            status_message=(
                f"[green]Prepared {profile} bundle and wrote {env_path.name}.[/green]"
            ),
        )
        self._refresh_preflight()

    def _generate_token_and_keys(self) -> None:
        settings = self._collect_settings()
        profile = "demo" if settings["mode"] == "mock" else "live"
        sensor_token = None
        app = self._sentinel_app()
        token_source = "local-generated"  # noqa: S105 - status label, not a secret
        try:
            if check_controller_online(settings["controller_url"]):
                sensor_token = request_sensor_token(
                    settings["controller_url"],
                    self.query_one("#input-admin-token", Input).value,
                    settings["sensor_id"],
                )
                token_source = "controller-api"  # noqa: S105 - status label
        except RuntimeError as exc:
            app.app_state.push_log(f"[Warn] Token bootstrap fallback: {exc}")
            token_source = "local-generated"  # noqa: S105 - status label

        if profile == "demo" and sensor_token is None:
            token_source = "demo-default"  # noqa: S105 - status label

        env_path = self._write_runtime_env(
            profile,
            settings["sensor_id"],
            sensor_token=sensor_token,
        )

        # Enhanced status with masked token preview
        env_text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        key_count = sum(
            1
            for line in env_text.splitlines()
            if "=" in line and not line.startswith("#")
        )
        token_preview = "(none)"  # noqa: S105 - UI label
        for line in env_text.splitlines():
            if line.startswith("SENSOR_AUTH_TOKEN="):
                raw = line.split("=", 1)[1].strip()
                token_preview = f"{raw[:6]}…{raw[-4:]}" if len(raw) > 12 else "(set)"
                break

        self._persist_setup_state(
            settings,
            status_message=(
                f"[green]✅ Token via {token_source} | "
                f"Token {token_preview} | "
                f"{key_count} keys in {env_path.name}[/green]"
            ),
        )
        self._refresh_preflight()

    def _apply_config_preset(self, preset_id: str) -> None:
        preset = BUILTIN_TUI_PRESETS[preset_id]
        merged = apply_tui_preset(preset_id, self._collect_settings())
        self._apply_settings_to_inputs(merged)
        self._persist_setup_state(self._collect_settings())
        self.query_one("#profile-status", Label).update(
            f"[green]Applied preset {preset['label']}.[/green]"
        )

    def _save_named_profile(self) -> None:
        name = self.query_one("#input-profile-name", Input).value
        try:
            saved_name = save_tui_profile(PROJECT_ROOT, name, self._collect_settings())
        except ValueError as exc:
            self.query_one("#profile-status", Label).update(
                f"[bold red]❌ {exc}[/bold red]"
            )
            return

        self.query_one("#input-profile-name", Input).value = saved_name
        self._persist_setup_state(self._collect_settings())
        self._refresh_profile_inventory()
        self.query_one("#profile-status", Label).update(
            f"[green]Saved custom profile '{saved_name}'.[/green]"
        )

    def _load_named_profile(self) -> None:
        name = self.query_one("#input-profile-name", Input).value.strip()
        # Fallback to selected profile from dropdown if name input is empty
        if not name:
            try:
                selected = self.query_one("#select-profile", Select).value
                if selected and selected != Select.BLANK:
                    name = str(selected)
            except Exception:  # noqa: S110
                pass
        profile = load_tui_profile(PROJECT_ROOT, name)
        if profile is None:
            self.query_one("#profile-status", Label).update(
                "[bold red]❌ Saved profile not found.[/bold red]"
            )
            return

        self._apply_settings_to_inputs(profile)
        self._persist_setup_state(self._collect_settings())
        self.query_one("#profile-status", Label).update(
            f"[green]Loaded custom profile '{profile['profile_name']}'.[/green]"
        )

    def _delete_named_profile(self) -> None:
        name = self.query_one("#input-profile-name", Input).value.strip()
        # Fallback to selected profile from dropdown if name input is empty
        if not name:
            try:
                selected = self.query_one("#select-profile", Select).value
                if selected and selected != Select.BLANK:
                    name = str(selected)
            except Exception:  # noqa: S110
                pass
        if not name or not delete_tui_profile(PROJECT_ROOT, name):
            self.query_one("#profile-status", Label).update(
                "[bold red]❌ Nothing to delete for that profile name.[/bold red]"
            )
            return

        current_settings = self._collect_settings()
        current_settings["profile_name"] = ""
        self.query_one("#input-profile-name", Input).value = ""
        self._persist_setup_state(current_settings)
        self._refresh_profile_inventory()
        self.query_one("#profile-status", Label).update(
            f"[green]Deleted custom profile '{name}'.[/green]"
        )

    def _refresh_profile_inventory(self) -> None:
        saved_profiles = list_saved_tui_profiles(PROJECT_ROOT)
        # Update the Select dropdown
        try:
            select_widget = self.query_one("#select-profile", Select)
            if saved_profiles:
                options = [(name, name) for name in saved_profiles]
                select_widget.set_options(options)
            else:
                select_widget.set_options([("(no saved profiles)", "")])
                select_widget.value = ""
        except Exception:  # noqa: S110
            pass

        # Update the inventory label
        if not saved_profiles:
            self.query_one("#profile-inventory", Label).update(
                "[dim]Saved profiles: none yet.[/dim]"
            )
            return

        preview = ", ".join(saved_profiles[:6])
        if len(saved_profiles) > 6:
            preview += ", ..."
        self.query_one("#profile-inventory", Label).update(
            f"[dim]Saved profiles:[/dim] {preview}"
        )

    def _refresh_profile_summary(self, settings: dict[str, Any]) -> None:
        normalized = normalize_tui_settings(settings)
        preset_id = str(normalized.get("preset_id", ""))
        preset_label = (
            BUILTIN_TUI_PRESETS[preset_id]["label"]
            if preset_id in BUILTIN_TUI_PRESETS
            else "Custom"
        )
        scrub_status = (
            "scrub probes" if normalized["scrub_probe_requests"] else "keep probes"
        )
        adaptive_status = (
            "adaptive hop" if normalized["adaptive_hopping"] else "fixed hop"
        )
        self.query_one("#preset-summary", Label).update(
            "[cyan]Preset:[/cyan] "
            f"{preset_label} | Capture {normalized['capture_method']} | "
            f"Channels {normalized['capture_channels']} | "
            f"Dwell {normalized['dwell_ms']}ms | Buffer "
            f"{normalized['buffer_max_items']} ({normalized['buffer_drop_policy']}) | "
            f"Detector {normalized['detector_profile']} | "
            f"{adaptive_status} | {scrub_status}"
        )

    @staticmethod
    def _extract_advanced_settings(settings: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_tui_settings(settings)
        keys = (
            "capture_method",
            "capture_channels",
            "dwell_ms",
            "adaptive_hopping",
            "buffer_max_items",
            "buffer_drop_policy",
            "scrub_probe_requests",
            "detector_profile",
            "preset_id",
        )
        return {key: normalized[key] for key in keys}

    def _sentinel_app(self) -> "SentinelTUIApp":
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        return app

    def _update_status_label(self, selector: str, markup: str) -> None:
        self.query_one(selector, Label).update(markup)

    def _run_setup_task(
        self,
        selector: str,
        pending_message: str,
        worker: Callable[[], Any],
        on_success: Callable[[Any], None],
    ) -> None:
        self._update_status_label(selector, f"[yellow]{pending_message}[/yellow]")

        def task() -> None:
            app = self._sentinel_app()
            try:
                result = worker()
            except Exception as exc:
                app.call_from_thread(
                    self._update_status_label,
                    selector,
                    f"[bold red]❌ {exc}[/bold red]",
                )
                return

            app.call_from_thread(on_success, result)

        threading.Thread(
            target=task,
            daemon=True,
            name=f"SetupTask-{selector.lstrip('#')}",
        ).start()

    def _handle_backend_check(self, report: BackendCheckReport) -> None:
        color = "green" if report.controller_online or report.docker_ready else "yellow"
        commands_ready = (
            ", ".join(
                name for name, enabled in report.command_status.items() if enabled
            )
            or "none"
        )
        self.query_one("#backend-status", Label).update(
            f"[{color}]Stack:[/{color}] {report.summary} | tools {commands_ready}"
        )
        self._sentinel_app().app_state.push_log(
            f"[Setup] Backend check -> {report.summary}"
        )

    def _handle_install_result(self, label: str, result: CommandResult) -> None:
        color = "green" if result.ok else "bold red"
        self.query_one("#backend-status", Label).update(
            f"[{color}]{label}:[/{color}] {result.summary}"
        )
        self._sentinel_app().app_state.push_log(
            f"[Setup] {label} install -> {result.summary}"
        )

    def _handle_lab_action(self, report: LabActionReport) -> None:
        color = "green" if report.ok else "bold red"
        self.query_one("#lab-status", Label).update(
            f"[{color}]Lab {report.action}:[/{color}] {report.summary}"
        )

        autofill_message = ""
        if report.ok and report.suggested_settings:
            merged_settings = {**self._collect_settings(), **report.suggested_settings}
            self._apply_settings_to_inputs(merged_settings)

            sensor_token = report.lab_env.get("SENSOR_AUTH_TOKEN")
            if sensor_token:
                env_path = self._write_runtime_env(
                    "live",
                    str(merged_settings["sensor_id"]),
                    sensor_token=sensor_token,
                )
                autofill_message = f"Synced runtime env from {env_path.name}"

            self._persist_setup_state(self._collect_settings())
            self._refresh_preflight()

            dashboard_user = report.lab_env.get("DASH_USERNAME")
            dashboard_password = report.lab_env.get("DASH_PASSWORD")
            creds_preview = ""
            if dashboard_user and dashboard_password:
                creds_preview = f" | GUI {dashboard_user}/{dashboard_password}"
            autofill_message = (
                f"Autofilled live fields from lab bootstrap{creds_preview}."
                if not autofill_message
                else f"{autofill_message}{creds_preview}"
            )

        self.query_one("#lab-autofill", Label).update(
            f"[dim]{autofill_message or report.details[:220]}[/dim]"
        )
        self._sentinel_app().app_state.push_log(
            f"[Setup] Lab {report.action} -> {report.summary}"
        )

    def _handle_gui_launch(self, result: CommandResult) -> None:
        color = "green" if result.ok else "bold red"
        self.query_one("#lab-status", Label).update(
            f"[{color}]GUI:[/{color}] {result.summary}"
        )

    def _handle_interface_inventory(self, report: WirelessInventoryReport) -> None:
        if report.selected_interface and report.selected_interface != "(none detected)":
            self.query_one("#input-iface", Input).value = report.selected_interface
            try:
                self.query_one(
                    "#select-iface", Select
                ).value = report.selected_interface
            except Exception:  # noqa: S110
                pass

        iface_names = [candidate.name for candidate in report.interfaces]
        self._available_ifaces = iface_names or ["(none detected)"]
        self._populate_iface_select(self._available_ifaces)

        color = "green" if iface_names else "yellow"
        self.query_one("#iface-status", Label).update(
            f"[{color}]Interface:[/{color}] {report.selected_interface or '(none)'}"
        )
        self.query_one("#iface-summary", Label).update(f"[dim]{report.summary}[/dim]")
        self._sentinel_app().app_state.push_log(
            f"[Setup] Interface detect -> {report.summary}"
        )

    def _handle_interface_mode_change(
        self,
        label: str,
        result: CommandResult,
    ) -> None:
        color = "green" if result.ok else "bold red"
        self.query_one("#iface-status", Label).update(
            f"[{color}]{label}:[/{color}] {result.summary}"
        )
        if result.stderr:
            # Clean up and wrap stderr for better display
            clean_err = result.stderr.replace("\n", " ").strip()
            self.query_one("#iface-summary", Label).update(
                f"[dim]Details: {clean_err[:300]}[/dim]"
            )
        else:
            self.query_one("#iface-summary", Label).update("")
        self._sentinel_app().app_state.push_log(f"[Setup] {label} -> {result.summary}")

    def _prod_health_url(self) -> str:
        return normalize_health_url(
            self.query_one("#input-prod-health-url", Input).value
        )

    def _refresh_runtime_operations(self) -> None:
        if self.app.screen is not self:
            return

        app = self._sentinel_app()
        daemon_snapshot = app.sensor_daemon_snapshot()
        daemon_color = (
            "green"
            if daemon_snapshot["running"]
            else ("red" if "Exited" in daemon_snapshot["status"] else "yellow")
        )
        self.query_one("#daemon-status", Label).update(
            f"Daemon: [{daemon_color}]{daemon_snapshot['status']}[/{daemon_color}]"
        )
        if daemon_snapshot["details"]:
            self.query_one("#daemon-details", Label).update(
                f"[dim]{daemon_snapshot['details']}[/dim]"
            )

        health_url = self._prod_health_url()
        health_ok = probe_health_endpoint(health_url)
        health_color = "green" if health_ok else "yellow"
        health_text = "ONLINE" if health_ok else "OFFLINE"
        self.query_one("#prod-health", Label).update(
            f"[{health_color}]Health:[/{health_color}] {health_text} | {health_url}"
        )

    def _append_rich_log(self, selector: str, message: str) -> None:
        text = message.rstrip("\n")
        widget = self.query_one(selector, RichLog)
        widget.write(text if text else "")

    @staticmethod
    def _display_path(path: Path) -> str:
        try:
            return str(path.relative_to(PROJECT_ROOT))
        except ValueError:
            return str(path)

    def _clear_audit_results(self) -> None:
        self.query_one("#audit-results", DataTable).clear(columns=False)
        self.query_one("#audit-log", RichLog).clear()
        self.query_one("#audit-status", Label).update("")
        self.query_one("#audit-summary", Label).update("")

    def _handle_audit_result(self, report: AuditRunReport) -> None:
        self._audit_running = False
        counts = report.report_data["summary"]["counts"]
        has_severe = counts.get("critical", 0) > 0 or counts.get("high", 0) > 0
        has_findings = any(counts.values())
        status_color = "red" if has_severe else ("yellow" if has_findings else "green")

        table = self.query_one("#audit-results", DataTable)
        table.clear(columns=False)
        findings = report.report_data.get("findings", [])
        if findings:
            for finding in findings:
                table.add_row(
                    str(finding.get("severity", "Info")).upper(),
                    str(finding.get("title", "Untitled")),
                    str(finding.get("status", "Open")),
                    str(finding.get("evidence_summary", "—")),
                    str(finding.get("remediation_summary", "—")),
                )
        else:
            table.add_row(
                "PASS",
                "No findings",
                "Closed",
                "No security issues detected.",
                "No action required.",
            )

        self.query_one("#audit-status", Label).update(
            f"[{status_color}]Audit complete:[/{status_color}] {report.summary}"
        )
        self.query_one("#audit-summary", Label).update(
            f"[dim]Profile {report.profile.upper()} | "
            f"Duration {report.duration_sec:.1f}s | "
            f"Saved {self._display_path(report.output_path)}[/dim]"
        )
        self._append_rich_log(
            "#audit-log",
            f"Completed audit in {report.duration_sec:.1f}s.",
        )
        self._sentinel_app().app_state.push_log(f"[Setup] Audit -> {report.summary}")

    def _handle_audit_failure(self, message: str) -> None:
        self._audit_running = False
        self.query_one("#audit-status", Label).update(
            f"[bold red]Audit failed:[/bold red] {message}"
        )
        self.query_one("#audit-summary", Label).update("")
        self._append_rich_log("#audit-log", f"ERROR: {message}")
        self._sentinel_app().app_state.push_log(f"[Setup] Audit failed -> {message}")

    def _launch_security_audit(self) -> None:
        if self._audit_running:
            self.query_one("#audit-status", Label).update(
                "[yellow]Audit already running…[/yellow]"
            )
            return

        settings = self._collect_settings()
        profile = self.query_one("#input-audit-profile", Input).value.strip() or "home"
        output_path = (
            self.query_one("#input-audit-output", Input).value.strip()
            or "artifacts/audit_report.json"
        )
        sensor_id = str(settings["sensor_id"])
        iface = str(settings["interface"])
        use_mock = self.query_one("#chk-audit-mock", Checkbox).value

        self._clear_audit_results()
        self._audit_running = True
        self.query_one("#audit-status", Label).update(
            "[yellow]Running security audit…[/yellow]"
        )
        self.query_one("#audit-summary", Label).update(
            f"[dim]Profile {profile} | Output {output_path}[/dim]"
        )

        def task() -> None:
            app = self._sentinel_app()

            def emit(message: str) -> None:
                app.call_from_thread(self._append_rich_log, "#audit-log", message)

            try:
                report = run_security_audit(
                    PROJECT_ROOT,
                    profile=profile,
                    output_path=output_path,
                    sensor_id=sensor_id,
                    iface=iface,
                    use_mock=use_mock,
                    progress=emit,
                )
            except Exception as exc:
                app.call_from_thread(self._handle_audit_failure, str(exc))
                return

            app.call_from_thread(self._handle_audit_result, report)

        threading.Thread(
            target=task,
            daemon=True,
            name="SetupAuditRunner",
        ).start()

    def _clear_diagnostics(self) -> None:
        self.query_one("#diag-log", RichLog).clear()
        self.query_one("#diag-status", Label).update("")

    def _finish_diagnostics_run(
        self,
        returncode: int | None,
        targets: tuple[str, ...],
        error: str | None = None,
    ) -> None:
        self._diagnostics_running = False
        target_label = ", ".join(targets)
        if error is not None:
            self.query_one("#diag-status", Label).update(
                f"[bold red]Diagnostics failed:[/bold red] {error}"
            )
            self._sentinel_app().app_state.push_log(
                f"[Setup] Diagnostics failed -> {error}"
            )
            return

        ok = returncode == 0
        color = "green" if ok else "red"
        summary = (
            f"Diagnostics passed for {target_label}."
            if ok
            else f"Diagnostics failed for {target_label} (exit {returncode})."
        )
        self.query_one("#diag-status", Label).update(f"[{color}]{summary}[/{color}]")
        self._append_rich_log("#diag-log", f"Process exited with code {returncode}.")
        self._sentinel_app().app_state.push_log(f"[Setup] Diagnostics -> {summary}")

    def _launch_diagnostics_run(self) -> None:
        if self._diagnostics_running:
            self.query_one("#diag-status", Label).update(
                "[yellow]Diagnostics already running…[/yellow]"
            )
            return

        targets = resolve_test_targets(
            include_unit=self.query_one("#chk-tests-unit", Checkbox).value,
            include_integration=self.query_one(
                "#chk-tests-integration",
                Checkbox,
            ).value,
            include_all=self.query_one("#chk-tests-all", Checkbox).value,
        )
        command = build_pytest_command(targets, python_executable=sys.executable)

        self._clear_diagnostics()
        self._diagnostics_running = True
        self.query_one("#diag-status", Label).update(
            f"[yellow]Running diagnostics for {', '.join(targets)}…[/yellow]"
        )

        def task() -> None:
            app = self._sentinel_app()
            app.call_from_thread(
                self._append_rich_log,
                "#diag-log",
                f"$ {' '.join(command)}",
            )
            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(PROJECT_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )  # noqa: S603,S607
                assert process.stdout is not None
                for raw_line in process.stdout:
                    app.call_from_thread(
                        self._append_rich_log,
                        "#diag-log",
                        raw_line.rstrip("\n"),
                    )
                returncode = process.wait()
            except Exception as exc:
                app.call_from_thread(
                    self._finish_diagnostics_run,
                    None,
                    targets,
                    str(exc),
                )
                return

            app.call_from_thread(
                self._finish_diagnostics_run,
                returncode,
                targets,
                None,
            )

        threading.Thread(
            target=task,
            daemon=True,
            name="SetupDiagnosticsRunner",
        ).start()

    def _start_background_daemon(self) -> None:
        tui_settings = self._collect_settings()
        validation_error = validate_tui_settings(
            tui_settings,
            available_ifaces=self._available_ifaces,
            file_exists=os.path.isfile,
        )
        if validation_error:
            self.query_one("#daemon-details", Label).update(
                f"[bold red]{validation_error}[/bold red]"
            )
            return

        self._persist_setup_state(tui_settings)
        result = self._sentinel_app().launch_sensor_daemon(tui_settings)
        color = "green" if result.ok else "bold red"
        self.query_one("#daemon-details", Label).update(
            f"[{color}]{result.summary}[/{color}]"
        )
        self._refresh_runtime_operations()

    def _stop_background_daemon(self) -> None:
        result = self._sentinel_app().stop_sensor_daemon()
        color = "green" if result.ok else "bold red"
        self.query_one("#daemon-details", Label).update(
            f"[{color}]{result.summary}[/{color}]"
        )
        self._refresh_runtime_operations()

    def _handle_prod_action(self, report: DeploymentActionReport) -> None:
        color = (
            "green"
            if report.ok and (report.action != "up" or report.health_ok)
            else ("yellow" if report.ok else "bold red")
        )
        self.query_one("#prod-status", Label).update(
            f"[{color}]Prod {report.action}:[/{color}] {report.summary}"
        )
        env_text = (
            self._display_path(report.env_file)
            if report.env_file is not None
            else "env missing"
        )
        self.query_one("#prod-details", Label).update(
            f"[dim]Env {env_text} | {report.details[:220]}[/dim]"
        )
        health_color = "green" if report.health_ok else "yellow"
        health_text = "ONLINE" if report.health_ok else "OFFLINE"
        self.query_one("#prod-health", Label).update(
            f"[{health_color}]Health:[/{health_color}] {health_text} | {report.health_url}"
        )
        self._sentinel_app().app_state.push_log(
            f"[Setup] Prod {report.action} -> {report.summary}"
        )

    def action_start_sensor(self) -> None:
        """Gather config, validate, and switch to Dashboard."""
        # ── Pre-flight Validation (Fool-proof) ──
        err_label = self.query_one("#validation-error", Label)
        tui_settings = self._collect_settings()
        validation_error = validate_tui_settings(
            tui_settings,
            available_ifaces=self._available_ifaces,
            file_exists=os.path.isfile,
        )
        if validation_error:
            err_label.update(f"[bold red]❌ {validation_error}[/bold red]")
            if "PCAP mode" in validation_error:
                self.query_one("#input-pcap", Input).focus()
            elif "Geo-Location" in validation_error:
                self.query_one("#input-geo-x", Input).focus()
            return

        err_label.update("")  # Clear errors

        # Push config into app state
        app = self._sentinel_app()
        state = app.app_state
        mode = str(tui_settings["mode"])
        iface = str(tui_settings["interface"])
        sensor_id = str(tui_settings["sensor_id"])
        runtime_iface = (
            iface if mode == "live" else ("pcap0" if mode == "pcap" else "mock0")
        )
        state.reset_session(mode=mode, sensor_id=sensor_id, interface=runtime_iface)
        self._persist_setup_state(tui_settings)

        # Switch to dashboard & start
        app.push_screen("dashboard")
        app.start_sensor_worker()


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 2: LIVE DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
class DashboardScreen(Screen):
    """Real-time monitoring dashboard with live wardrive context."""

    BINDINGS = [
        Binding("f1", "show_setup", "Setup"),
        Binding("f2", "force_channel_hop", "Force Channel"),
        Binding("space", "toggle_pause", "Pause Log"),
        Binding("c", "force_channel_hop", "Force Channel"),
        Binding("m", "mark_bssid", "Mark BSSID"),
        Binding("q", "graceful_quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("", id="dashboard-status")
        with Horizontal(id="dashboard-area"):
            # ── LEFT: System Health ──
            with Vertical(id="left-panel"):
                yield Label("[b]🖥️  SYSTEM HEALTH[/b]", classes="panel-title")
                yield Label("", id="sys-cpu")
                yield Label("", id="sys-mem")
                yield Label("", id="sys-usb")
                yield Label("", id="sys-uptime")
                yield Label("")
                yield Label("[b]📦  SPOOL QUEUE[/b]", classes="panel-title")
                yield Label("", id="spool-queued")
                yield Label("", id="spool-inflight")
                yield Label("", id="spool-dropped")
                yield Label("")
                yield Label("[b]🔒  SECURITY POSTURE[/b]", classes="panel-title")
                yield Label("", id="sec-open")
                yield Label("", id="sec-wep")
                yield Label("", id="sec-wpa2")
                yield Label("", id="sec-wpa3")
                yield Label("")
                yield Label("[b]📡  SENSOR[/b]", classes="panel-title")
                yield Label("", id="sen-id")
                yield Label("", id="sen-mode")
                yield Label("", id="sen-iface")
                yield Label("", id="sen-nets")

            # ── CENTER: Networks + Alerts ──
            with Vertical(id="center-area"):
                with Container(id="network-panel"):
                    yield Label("[b]📶  LIVE NETWORK FEED[/b]", classes="panel-title")
                    table: DataTable = DataTable(id="net-table")
                    table.cursor_type = "row"
                    table.zebra_stripes = True
                    yield table

                with Horizontal(id="bottom-row"):
                    with Container(id="alert-panel"):
                        yield Label("[b]🚨  THREAT ALERTS[/b]", classes="panel-title")
                        yield RichLog(
                            id="alert-log",
                            max_lines=100,
                            highlight=True,
                            markup=True,
                        )

                    with Vertical(id="wardrive-panel"):
                        yield Label("[b]🛰️  WARDRIVE / GPS[/b]", classes="panel-title")
                        yield Label("", id="wardrive-status")
                        yield Label("", id="wardrive-source")
                        yield Label("", id="wardrive-summary")
                        yield Label("", id="wardrive-last-fix")
                        yield Label("", id="wardrive-recent")

            # ── RIGHT: Log Stream ──
            with Vertical(id="right-panel"):
                yield Label("[b]📄  LOG STREAM[/b]", classes="panel-title")
                yield RichLog(
                    id="sys-log",
                    max_lines=300,
                    highlight=True,
                    markup=True,
                )

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#net-table", DataTable)
        table.add_columns("Time", "BSSID", "SSID", "RSSI", "Ch", "Security")

    def action_show_setup(self) -> None:
        self.app.pop_screen()

    def action_toggle_pause(self) -> None:
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        app.log_paused = not app.log_paused
        status = "⏸ PAUSED" if app.log_paused else "▶ RESUMED"
        app.app_state.push_log(f"[System] Log scroll {status}")

    def action_force_channel_hop(self) -> None:
        """Force WiFi channel hop (sends signal to channel hopper)."""
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        if app.force_channel_hop():
            app.app_state.push_log("[System] ⚡ Forced channel hop")
        else:
            app.app_state.push_log("[System] Channel hop unavailable in current mode")

    def action_mark_bssid(self) -> None:
        """Mark the currently selected BSSID as suspicious."""
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        try:
            table = self.query_one("#net-table", DataTable)
            row_key = table.cursor_row
            if row_key is not None:
                # Get BSSID from column 1
                row_data = table.get_row_at(row_key)
                bssid = str(row_data[1]) if len(row_data) > 1 else "?"
                app.app_state.push_log(
                    f"[System] 🔖 Marked BSSID as suspicious: {bssid}"
                )
                app.app_state.push_alert(
                    AlertEntry(
                        timestamp=datetime.now().strftime("%H:%M:%S"),
                        severity="Medium",
                        title="Manual Mark",
                        description=f"User marked {bssid} as suspicious",
                    )
                )
        except Exception:  # noqa: S110
            pass

    def action_graceful_quit(self) -> None:
        """Graceful shutdown with visual feedback."""
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        app.begin_shutdown()
        app.push_screen(ShutdownModal())


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════
class SentinelTUIApp(App):
    """Sentinel NetLab – Multi-Screen Terminal Dashboard."""

    TITLE = "Sentinel NetLab"
    SUB_TITLE = "Terminal Control Panel v1.0.0"
    CSS_PATH = "theme.tcss"

    SCREENS = {"setup": SetupScreen, "dashboard": DashboardScreen}

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.app_state = AppState()
        self.tui_config: dict = {}
        self.env_load_result = load_tui_env(
            PROJECT_ROOT,
            os.environ.get("SENTINEL_ENV_FILE"),
        )
        self.config_path = resolve_config_path(PROJECT_ROOT)
        self.saved_settings = load_saved_tui_settings(self.config_path)
        self.wardrive_path = resolve_wardrive_session_path(
            PROJECT_ROOT,
            os.environ.get("WARDRIVE_SESSION_FILE"),
        )
        self._wardrive_snapshot = WardriveSnapshot(source_path=self.wardrive_path)
        self.log_paused = False
        self._sensor_thread: threading.Thread | None = None
        self._controller: SensorController | None = None
        self._tui_handler: TUILogHandler | None = None
        self._stop_event = threading.Event()
        self._shutdown_complete = threading.Event()
        self._external_sensor_process: subprocess.Popen[str] | None = None
        self._external_sensor_log_handle: Any | None = None
        self._external_sensor_log_path = (
            PROJECT_ROOT / "artifacts" / "tui-sensor-daemon.log"
        )
        self._external_sensor_last_exit: int | None = None
        self._external_sensor_command: list[str] = []
        # Alert debouncing: track recent alert keys to group duplicates
        self._alert_debounce: dict[str, int] = {}
        self._debounce_window = 10.0  # seconds
        self._last_debounce_flush = time.time()

    def on_mount(self) -> None:
        self.push_screen("setup")
        self.set_interval(REFRESH_INTERVAL, self._update_dashboard)

    def start_sensor_worker(self) -> None:
        """Launch the SensorController in a background thread."""
        if self._sensor_thread and self._sensor_thread.is_alive():
            return

        self._stop_event.clear()
        self._shutdown_complete.clear()

        # Install log handler
        self._ensure_log_handler()

        self._sensor_thread = threading.Thread(
            target=self._run_sensor, daemon=True, name="SensorWorker"
        )
        self._sensor_thread.start()
        self.app_state.push_log("[System] Sensor Worker started.")

    def _run_sensor(self) -> None:
        """Run the SensorController in a background thread."""
        controller: SensorController | None = None
        try:
            config = self._build_runtime_config()
            controller = SensorController(
                config=config,
                on_network=self._handle_network_event,
                on_alert=self._handle_alert_event,
            )
            self._controller = controller
            self.app_state.start_time = time.time()
            self.app_state.running = True
            self.app_state.push_log(
                "[System] Starting SensorController "
                f"mode={self.tui_config.get('mode', 'mock')} "
                f"iface={config.capture.interface}"
            )

            if not controller.start():
                self.app_state.push_log("[Error] Sensor failed to start.")
                return

            while not self._stop_event.is_set() and controller._running:
                time.sleep(0.2)

            if controller._running:
                controller.stop()

            if controller._fatal_exit_code is not None:
                self.app_state.push_log(
                    f"[Error] Sensor stopped by fail-fast policy "
                    f"(exit={controller._fatal_exit_code})"
                )

        except Exception as e:
            self.app_state.push_log(f"[Error] Sensor worker failed: {e}")
        finally:
            self.app_state.running = False
            self._controller = None
            self._shutdown_complete.set()

    def _ensure_log_handler(self) -> None:
        if self._tui_handler is not None:
            return

        self._tui_handler = TUILogHandler(self.app_state)
        self._tui_handler.setLevel(logging.INFO)
        root_logger = logging.getLogger()
        root_logger.addHandler(self._tui_handler)
        root_logger.setLevel(logging.INFO)

    def _build_runtime_config(self):
        try:
            config = (
                init_config(str(self.config_path))
                if self.config_path is not None
                else init_config()
            )
        except Exception as e:
            self.app_state.push_log(
                f"[Warn] Falling back to local config defaults: {e}"
            )
            config = Config()
            self._apply_raw_config(config, load_raw_config(self.config_path))

        cfg = self.tui_config
        mode = cfg.get("mode", "mock")

        config.sensor.id = cfg.get("sensor_id", config.sensor.id)
        config.mock_mode = mode == "mock"
        if mode == "mock":
            config.capture.interface = "mock0"
        elif mode == "pcap":
            config.capture.interface = cfg.get("interface", config.capture.interface)
        else:
            config.capture.interface = cfg.get("interface", config.capture.interface)
        config.capture.pcap_file = cfg.get("pcap_path") if mode == "pcap" else None
        config.capture.pcap_loop = bool(cfg.get("pcap_loop", True))
        config.capture.pcap_realtime = bool(cfg.get("pcap_realtime", True))
        config.api.upload_url = build_upload_url(cfg.get("controller_url"))
        config.ml.enabled = bool(cfg.get("ml_enabled"))
        config.geo.enabled = bool(cfg.get("geo_enabled"))
        config.geo.sensor_x_m = parse_geo_coordinate(cfg.get("geo_sensor_x_m"))
        config.geo.sensor_y_m = parse_geo_coordinate(cfg.get("geo_sensor_y_m"))
        config.privacy.anonymize_ssid = bool(cfg.get("anonymize"))
        config.detectors.default_profile = str(cfg.get("det_profile", "lite_realtime"))
        if hasattr(config.capture, "method"):
            config.capture.method = str(
                cfg.get("capture_method", config.capture.method)
            )
        if hasattr(config.capture, "channels"):
            config.capture.channels = parse_channel_list(
                cfg.get("capture_channels", config.capture.channels)
            )
        if hasattr(config.capture, "dwell_time"):
            config.capture.dwell_time = (
                float(str(cfg.get("dwell_ms", "200")).strip()) / 1000.0
            )
        if hasattr(config.capture, "adaptive_hopping"):
            config.capture.adaptive_hopping = bool(cfg.get("adaptive_hopping"))
        if hasattr(config, "buffer"):
            config.buffer.max_items = int(str(cfg.get("buffer_max_items", "10000")))
            config.buffer.drop_policy = str(
                cfg.get("buffer_drop_policy", config.buffer.drop_policy)
            )
        if hasattr(config.privacy, "scrub_probe_requests"):
            config.privacy.scrub_probe_requests = bool(cfg.get("scrub_probe_requests"))
        config.detectors.default_profile = str(
            cfg.get("detector_profile", config.detectors.default_profile)
        )

        return config

    @staticmethod
    def _apply_raw_config(config: Config, data: dict[str, Any]) -> None:
        """Apply a minimal YAML/JSON mapping onto the runtime Config object."""
        section_map = {
            "buffer": config.buffer,
            "storage": config.storage,
            "api": config.api,
            "risk": config.risk,
            "privacy": config.privacy,
            "ml": config.ml,
            "geo": config.geo,
            "detectors": config.detectors,
        }

        sensor_section = data.get("sensor", {})
        if isinstance(sensor_section, dict):
            if "id" in sensor_section:
                config.sensor.id = sensor_section["id"]
            legacy_interface = sensor_section.get("interface")
            if legacy_interface:
                config.capture.interface = legacy_interface

        capture_section = data.get("capture", {})
        if isinstance(capture_section, dict):
            for key, value in capture_section.items():
                if key == "dwell_ms":
                    config.capture.dwell_time = float(value) / 1000.0
                elif hasattr(config.capture, key):
                    setattr(config.capture, key, value)

        for section_name, section_obj in section_map.items():
            values = data.get(section_name, {})
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if hasattr(section_obj, key):
                    setattr(section_obj, key, value)

        if "mock_mode" in data:
            config.mock_mode = bool(data["mock_mode"])
        if "log_level" in data:
            config.log_level = str(data["log_level"])
        logging_section = data.get("logging", {})
        if isinstance(logging_section, dict) and logging_section.get("level"):
            config.log_level = str(logging_section["level"])

    def _handle_network_event(self, net_dict: dict[str, Any]) -> None:
        network = self._network_entry_from_payload(net_dict)
        self.app_state.record_network(network)

    def _handle_alert_event(self, alert_dict: dict[str, Any]) -> None:
        alert = AlertEntry(
            timestamp=_format_event_time(
                alert_dict.get("timestamp") or alert_dict.get("timestamp_utc")
            ),
            severity=str(alert_dict.get("severity", "Low")).title(),
            title=str(alert_dict.get("title", "Alert")),
            description=str(
                alert_dict.get("description")
                or alert_dict.get("message")
                or alert_dict.get("alert_type", "Sensor event")
            ),
        )
        self.app_state.record_alert(alert)

    def _network_entry_from_payload(self, net_dict: dict[str, Any]) -> NetworkEntry:
        raw_rssi = net_dict.get("rssi_dbm")
        rssi = int(raw_rssi) if isinstance(raw_rssi, (int, float)) else None
        raw_channel = net_dict.get("channel")
        channel = int(raw_channel) if isinstance(raw_channel, (int, float)) else None
        security = str(net_dict.get("security") or "UNKNOWN").upper()

        return NetworkEntry(
            timestamp=_format_event_time(net_dict.get("timestamp_utc")),
            bssid=str(net_dict.get("bssid", "—")),
            ssid=str(net_dict.get("ssid") or "<hidden>"),
            rssi=rssi,
            channel=channel,
            security=security,
        )

    def _sync_controller_state(self) -> None:
        controller = self._controller
        if controller is None:
            return

        try:
            self.app_state.update_from_status(controller.status())
        except Exception:
            logger.debug("Failed to sync controller status", exc_info=True)

    def force_channel_hop(self) -> bool:
        controller = self._controller
        if controller is None:
            return False
        try:
            return controller.force_channel_hop()
        except Exception as e:
            self.app_state.push_log(f"[Error] Channel hop failed: {e}")
            return False

    def _sync_wardrive_snapshot(self) -> WardriveSnapshot:
        self._wardrive_snapshot = load_wardrive_snapshot(self.wardrive_path)
        return self._wardrive_snapshot

    def begin_shutdown(self) -> None:
        if self._stop_event.is_set():
            return
        self.app_state.push_log("[System] Graceful shutdown requested")
        self._stop_event.set()
        if self._sensor_thread is None or not self._sensor_thread.is_alive():
            self._shutdown_complete.set()

    def is_shutdown_complete(self) -> bool:
        return self._shutdown_complete.is_set()

    def _cleanup_external_sensor_handle(self) -> None:
        handle = self._external_sensor_log_handle
        if handle is not None:
            try:
                handle.flush()
                handle.close()
            except Exception:
                logger.debug("Failed to close sensor daemon log handle", exc_info=True)
        self._external_sensor_log_handle = None

    def sensor_daemon_snapshot(self) -> dict[str, Any]:
        process = self._external_sensor_process
        log_path = self._external_sensor_log_path

        if process is not None:
            returncode = process.poll()
            if returncode is None:
                details = f"PID {process.pid} | log {log_path.name}"
                return {"running": True, "status": "Running", "details": details}

            self._external_sensor_last_exit = returncode
            self._external_sensor_process = None
            self._cleanup_external_sensor_handle()
            return {
                "running": False,
                "status": f"Exited ({returncode})",
                "details": f"Last log {log_path.name}",
            }

        if self._external_sensor_last_exit is not None:
            return {
                "running": False,
                "status": f"Exited ({self._external_sensor_last_exit})",
                "details": f"Last log {log_path.name}",
            }

        return {
            "running": False,
            "status": "Stopped",
            "details": f"Log {log_path.name} will be created on launch.",
        }

    def launch_sensor_daemon(self, settings: dict[str, Any]) -> CommandResult:
        snapshot = self.sensor_daemon_snapshot()
        if snapshot["running"]:
            return CommandResult(
                ok=False,
                summary=f"Sensor daemon is already running ({snapshot['details']}).",
                returncode=1,
            )

        command = build_sensor_daemon_command(
            settings,
            config_path=self.config_path,
            python_executable=sys.executable,
        )
        log_path = self._external_sensor_log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("a", encoding="utf-8")
        log_handle.write(
            f"\n[{datetime.now().isoformat()}] Launching: {' '.join(command)}\n"
        )
        log_handle.flush()

        try:
            process = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )  # noqa: S603,S607
        except Exception as exc:
            log_handle.write(f"[launcher-error] {exc}\n")
            log_handle.flush()
            log_handle.close()
            return CommandResult(
                ok=False,
                summary=f"Failed to start sensor daemon: {exc}",
                returncode=1,
            )

        self._external_sensor_process = process
        self._external_sensor_log_handle = log_handle
        self._external_sensor_last_exit = None
        self._external_sensor_command = command
        self.app_state.push_log(
            f"[System] Background daemon launched (pid={process.pid}) -> {log_path.name}"
        )
        return CommandResult(
            ok=True,
            summary=f"Sensor daemon started (pid {process.pid}). Log: {log_path.name}",
            returncode=0,
        )

    def stop_sensor_daemon(self) -> CommandResult:
        process = self._external_sensor_process
        if process is None or process.poll() is not None:
            self.sensor_daemon_snapshot()
            return CommandResult(
                ok=False,
                summary="Sensor daemon is not running.",
                returncode=1,
            )

        process.terminate()
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait(timeout=5)

        self._external_sensor_last_exit = returncode
        self._external_sensor_process = None
        self._cleanup_external_sensor_handle()
        self.app_state.push_log(
            f"[System] Background daemon stopped (exit={returncode})."
        )
        return CommandResult(
            ok=True,
            summary=f"Sensor daemon stopped (exit {returncode}).",
            returncode=returncode,
        )

    # ─── Alert Debouncing ────────────────────────────────────────────────
    def _debounce_alert(self, alert: AlertEntry) -> AlertEntry | None:
        """Group duplicate alerts within the debounce window.
        Returns the alert to display, or None if suppressed."""
        key = f"{alert.title}:{alert.severity}"
        now = time.time()

        # Flush old keys
        if now - self._last_debounce_flush > self._debounce_window:
            self._alert_debounce.clear()
            self._last_debounce_flush = now

        count = self._alert_debounce.get(key, 0) + 1
        self._alert_debounce[key] = count

        if count == 1:
            return alert  # First occurrence, show immediately
        elif count <= 5:
            return None  # Suppress (will be grouped)
        else:
            # Show grouped summary
            self._alert_debounce[key] = 0
            return AlertEntry(
                timestamp=alert.timestamp,
                severity=alert.severity,
                title=alert.title,
                description=f"({count}x) {alert.description[:60]}",
            )

    # ─── Dashboard Refresh ───────────────────────────────────────────────
    def _update_dashboard(self) -> None:
        if not isinstance(self.screen, DashboardScreen):
            return

        self._sync_controller_state()
        wardrive = self._sync_wardrive_snapshot()
        state = self.app_state
        state.update_resources()
        screen = self.screen

        # ── Dashboard Status Banner ──
        try:
            if state.running:
                banner = (
                    f"[bold green]● SENSOR ACTIVE[/bold green]  "
                    f"[dim]{state.mode.upper()} | {state.interface} | "
                    f"{state.sensor_id} | {state.uptime}[/dim]"
                )
            else:
                banner = (
                    "[bold yellow]○ SENSOR IDLE[/bold yellow]  "
                    "[dim]Waiting for sensor start…[/dim]"
                )
            screen.query_one("#dashboard-status", Label).update(banner)
        except Exception:  # noqa: S110
            pass

        # ── System Health ──
        try:
            screen.query_one("#sys-cpu", Label).update(
                f"CPU:    [{self._color_pct(state.cpu_percent)}]"
                f"{state.cpu_percent:.0f}%[/]"
            )
            screen.query_one("#sys-mem", Label).update(
                f"RAM:    [{self._color_pct(state.mem_percent)}]"
                f"{state.mem_percent:.0f}%[/]"
            )
            screen.query_one("#sys-usb", Label).update(
                (
                    "USB:    "
                    f"[{'red' if 'Disconnected' in state.usb_status else 'green'}]"
                    f"{state.usb_status or state.interface}[/]"
                )
                if state.running
                else "USB:    [yellow]Idle[/yellow]"
            )
            screen.query_one("#sys-uptime", Label).update(
                f"Uptime: [dim]{state.uptime}[/dim]"
            )

            # Spool
            q_color = (
                "red"
                if state.spool_queued > 20
                else ("yellow" if state.spool_queued > 5 else "green")
            )
            screen.query_one("#spool-queued", Label).update(
                f"Queued:   [{q_color}]{state.spool_queued}[/{q_color}]"
            )
            screen.query_one("#spool-inflight", Label).update(
                f"Inflight: {state.spool_inflight}"
            )
            screen.query_one("#spool-dropped", Label).update(
                f"Dropped:  {state.spool_dropped}"
            )

            # Security
            screen.query_one("#sec-open", Label).update(
                f"Open: [{'red' if state.sec_open else 'green'}]{state.sec_open}[/]"
            )
            screen.query_one("#sec-wep", Label).update(
                f"WEP:  [{'dark_orange' if state.sec_wep else 'green'}]"
                f"{state.sec_wep}[/]"
            )
            screen.query_one("#sec-wpa2", Label).update(
                f"WPA2: [cyan]{state.sec_wpa2}[/cyan]"
            )
            screen.query_one("#sec-wpa3", Label).update(
                f"WPA3: [bright_green]{state.sec_wpa3}[/bright_green]"
            )

            # Sensor
            screen.query_one("#sen-id", Label).update(
                f"ID:    [cyan]{state.sensor_id}[/cyan]"
            )
            screen.query_one("#sen-mode", Label).update(
                f"Mode:  [{'green' if state.running else 'yellow'}]"
                f"{state.mode.upper()}[/]"
            )
            screen.query_one("#sen-iface", Label).update(
                f"Iface: {state.interface}  [dim]{state.channel_current}[/dim]"
            )
            screen.query_one("#sen-nets", Label).update(
                f"Nets:  [cyan]{state.total_networks}[/cyan]"
            )
        except Exception:  # noqa: S110
            pass

        # ── Wardrive / GPS ──
        try:
            waiting_for_wardrive = "Waiting" in wardrive.status
            wardrive_updating = "updating" in wardrive.status.lower()
            status_color = (
                "green"
                if wardrive.recent_sightings
                else ("yellow" if waiting_for_wardrive or wardrive_updating else "red")
            )
            screen.query_one("#wardrive-status", Label).update(
                f"Status: [{status_color}]{wardrive.status}[/{status_color}]"
            )
            screen.query_one("#wardrive-source", Label).update(
                f"Source: [dim]{wardrive.source_path.name}[/dim]"
            )
            screen.query_one("#wardrive-summary", Label).update(
                "Session: "
                f"[cyan]{wardrive.sensor_id}[/cyan]  "
                f"Nets [cyan]{wardrive.unique_networks}[/cyan]  "
                f"Sightings [cyan]{wardrive.total_sightings}[/cyan]  "
                f"GPS [cyan]{wardrive.gps_points}[/cyan]"
            )
            screen.query_one("#wardrive-last-fix", Label).update(
                f"Last: [dim]{wardrive.last_update}[/dim]  "
                f"Fix: [cyan]{wardrive.last_fix}[/cyan]"
            )

            if wardrive.recent_sightings:
                lines = []
                for sighting in wardrive.recent_sightings:
                    sec_color = self._security_color(sighting.security)
                    rssi_text = (
                        f"{sighting.rssi_dbm}dBm"
                        if sighting.rssi_dbm is not None
                        else "—"
                    )
                    lines.append(
                        f"[dim]{sighting.timestamp}[/dim] "
                        f"[{sec_color}]{sighting.security}[/{sec_color}] "
                        f"{sighting.ssid} "
                        f"[dim]{rssi_text}[/dim]\n"
                        f"[dim]{sighting.bssid} @ {sighting.gps_label}[/dim]"
                    )
                recent_markup = "\n".join(lines)
            else:
                recent_markup = "[dim]No wardrive sightings yet.[/dim]"

            screen.query_one("#wardrive-recent", Label).update(recent_markup)
        except Exception:  # noqa: S110
            pass

        # ── Drain network queue ──
        try:
            table = screen.query_one("#net-table", DataTable)
            drained = 0
            while drained < 20:
                try:
                    net = state.network_queue.get_nowait()
                    rssi_str = str(net.rssi) if net.rssi is not None else "—"
                    if net.rssi is not None:
                        if net.rssi > -50:
                            rssi_display = Text(f"{rssi_str} dBm", style="bold green")
                        elif net.rssi > -70:
                            rssi_display = Text(f"{rssi_str} dBm", style="bold yellow")
                        else:
                            rssi_display = Text(f"{rssi_str} dBm", style="bold red")
                    else:
                        rssi_display = Text("—", style="dim")

                    sec = net.security.upper()
                    if "OPEN" in sec:
                        sec_display = Text(sec, style="bold red")
                    elif "WEP" in sec:
                        sec_display = Text(sec, style="bold dark_orange")
                    elif "WPA3" in sec:
                        sec_display = Text(sec, style="bold bright_green")
                    else:
                        sec_display = Text(sec, style="bold cyan")

                    table.add_row(
                        net.timestamp,
                        net.bssid,
                        net.ssid,
                        rssi_display,
                        str(net.channel or "—"),
                        sec_display,
                    )
                    drained += 1
                except queue.Empty:
                    break

            while table.row_count > 50:
                table.remove_row(next(iter(table.rows)))
        except Exception:  # noqa: S110
            pass

        # ── Drain alerts (with debouncing) ──
        try:
            alert_log = screen.query_one("#alert-log", RichLog)
            while True:
                try:
                    alert = state.alert_queue.get_nowait()
                    debounced = self._debounce_alert(alert)
                    if debounced is None:
                        continue

                    sev_color = {
                        "Critical": "bold white on red",
                        "High": "bold red",
                        "Medium": "yellow",
                        "Low": "cyan",
                    }.get(debounced.severity, "white")

                    alert_log.write(
                        Text.from_markup(
                            f"[dim]{debounced.timestamp}[/dim] "
                            f"[{sev_color}]🚨 "
                            f"{debounced.severity.upper()}[/{sev_color}] "
                            f"{debounced.title}: {debounced.description[:80]}"
                        )
                    )
                except queue.Empty:
                    break
        except Exception:  # noqa: S110
            pass

        # ── Drain system log ──
        if not self.log_paused:
            try:
                sys_log = screen.query_one("#sys-log", RichLog)
                drained = 0
                while drained < 30:
                    try:
                        msg = state.log_queue.get_nowait()
                        sys_log.write(msg)
                        drained += 1
                    except queue.Empty:
                        break
            except Exception:  # noqa: S110
                pass

    @staticmethod
    def _color_pct(pct: float) -> str:
        if pct > 80:
            return "red"
        elif pct > 50:
            return "yellow"
        return "green"

    @staticmethod
    def _security_color(security: str) -> str:
        sec = security.upper()
        if "OPEN" in sec:
            return "red"
        if "WEP" in sec:
            return "dark_orange"
        if "WPA3" in sec:
            return "bright_green"
        return "cyan"


# ─── Entry Point ─────────────────────────────────────────────────────────────
def main():
    app = SentinelTUIApp()
    app.run()


if __name__ == "__main__":
    main()
