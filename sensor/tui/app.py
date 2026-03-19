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
import threading
import time
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
)

from sensor.config import Config, init_config
from sensor.sensor_controller import SensorController
from sensor.tui.bootstrap import EnvLoadResult, load_tui_env
from sensor.tui.config_store import (
    coerce_sensor_id,
    load_raw_config,
    load_saved_tui_settings,
    parse_geo_coordinate,
    persist_tui_settings,
    resolve_config_path,
    validate_tui_settings,
)
from sensor.tui.setup_wizard import (
    build_bootstrap_env,
    build_quick_profile,
    build_upload_url,
    normalize_controller_url,
    request_sensor_token,
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
        resp = urllib.request.urlopen(  # noqa: S310 # nosec B310
            f"{url}/api/v1/sensors", timeout=1
        )
        return bool(resp.getcode() == 200)
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
                        yield Button("Gen Token/Keys", id="btn-gen-secrets")
                    with Horizontal(classes="setup-row", id="row-controller-url"):
                        yield Label("Controller URL", classes="setup-label")
                        yield Input(
                            value="http://127.0.0.1:8080",
                            placeholder="http://127.0.0.1:8080",
                            id="input-controller-url",
                            classes="setup-input",
                            compact=True,
                        )
                    with Horizontal(classes="setup-row", id="row-admin-token"):
                        yield Label("Admin Token", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="Optional, used to auto-create sensor token",
                            password=True,
                            id="input-admin-token",
                            classes="setup-input",
                            compact=True,
                        )
                    yield Label("", id="quick-setup-status")

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

                # Interface
                with Container(classes="setup-group"):
                    yield Label("🔌 CONFIGURATION", classes="setup-group-title")
                    with Horizontal(classes="setup-row", id="row-sensor-id"):
                        yield Label("Sensor ID", classes="setup-label")
                        yield Input(
                            value="tui-sensor-01",
                            placeholder="Unique sensor identifier",
                            id="input-sensor-id",
                            classes="setup-input",
                            compact=True,
                        )
                    with Horizontal(classes="setup-row", id="row-interface"):
                        yield Label("Interface", classes="setup-label")
                        yield Input(
                            value="wlan0mon",
                            placeholder="WiFi interface",
                            id="input-iface",
                            classes="setup-input",
                            compact=True,
                        )
                    with Horizontal(classes="setup-row", id="row-pcap"):
                        yield Label("PCAP Path", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="/path/to/capture.pcap",
                            id="input-pcap",
                            classes="setup-input",
                            compact=True,
                        )
                    with Horizontal(classes="setup-row", id="row-geo-x"):
                        yield Label("Geo Sensor X", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="e.g. 12.5",
                            id="input-geo-x",
                            classes="setup-input",
                            compact=True,
                        )
                    with Horizontal(classes="setup-row", id="row-geo-y"):
                        yield Label("Geo Sensor Y", classes="setup-label")
                        yield Input(
                            value="",
                            placeholder="e.g. 4.0",
                            id="input-geo-y",
                            classes="setup-input",
                            compact=True,
                        )

                # Toggles
                with Container(classes="setup-group"):
                    yield Label("🧠 FEATURES", classes="setup-group-title")
                    yield Checkbox("Enable ML Boost", id="chk-ml", value=False)
                    yield Checkbox("Enable Geo-Location", id="chk-geo", value=False)
                    yield Checkbox(
                        "Anonymize MAC/SSID (Quyền riêng tư)", id="chk-anon", value=True
                    )

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
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        defaults = app.saved_settings
        self._available_ifaces = detect_wifi_interfaces()
        sensor_id = coerce_sensor_id(
            defaults.get("sensor_id"),
            os.environ.get("SENSOR_ID", "tui-sensor-01"),
        )

        # Auto-fill best interface
        if defaults.get("interface"):
            self.query_one("#input-iface", Input).value = str(defaults["interface"])
        elif self._available_ifaces[0] != "(none detected)":
            # Prefer monitor mode interfaces
            best = next(
                (i for i in self._available_ifaces if "mon" in i),
                self._available_ifaces[0],
            )
            self.query_one("#input-iface", Input).value = best

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
        self.query_one("#input-geo-x", Input).value = str(
            defaults.get("geo_sensor_x_m", "")
        )
        self.query_one("#input-geo-y", Input).value = str(
            defaults.get("geo_sensor_y_m", "")
        )
        self.query_one("#chk-ml", Checkbox).value = bool(defaults.get("ml_enabled"))
        self.query_one("#chk-geo", Checkbox).value = bool(defaults.get("geo_enabled"))
        self.query_one("#chk-anon", Checkbox).value = bool(
            defaults.get("anonymize", True)
        )

        mode = defaults.get("mode", "mock")
        self.query_one("#mode-live", RadioButton).value = mode == "live"
        self.query_one("#mode-mock", RadioButton).value = mode == "mock"
        self.query_one("#mode-pcap", RadioButton).value = mode == "pcap"

        self._sync_dynamic_rows()
        self._refresh_preflight()
        self.call_after_refresh(
            lambda: self.set_focus(self.query_one("#input-sensor-id", Input))
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.action_start_sensor()
        elif event.button.id == "btn-quick-demo":
            self._apply_quick_bundle("demo")
        elif event.button.id == "btn-quick-live":
            self._apply_quick_bundle("live")
        elif event.button.id == "btn-gen-secrets":
            self._generate_token_and_keys()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk-geo":
            self._sync_dynamic_rows()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode-select":
            self._sync_dynamic_rows()

    def _refresh_preflight(self) -> None:
        app = self.app
        assert isinstance(app, SentinelTUIApp)

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
        self.query_one("#row-pcap", Horizontal).display = mode == "pcap"
        self.query_one("#row-geo-x", Horizontal).display = geo_enabled
        self.query_one("#row-geo-y", Horizontal).display = geo_enabled

    def _selected_mode(self) -> str:
        if self.query_one("#mode-live", RadioButton).value:
            return "live"
        if self.query_one("#mode-pcap", RadioButton).value:
            return "pcap"
        return "mock"

    def _controller_url(self) -> str:
        return normalize_controller_url(
            self.query_one("#input-controller-url", Input).value
        )

    def _collect_settings(self) -> dict[str, Any]:
        mode = self._selected_mode()
        iface = self.query_one("#input-iface", Input).value.strip()
        pcap_path = self.query_one("#input-pcap", Input).value
        sensor_id = coerce_sensor_id(
            self.query_one("#input-sensor-id", Input).value,
            os.environ.get("SENSOR_ID")
            or self.app.saved_settings.get("sensor_id")
            or "tui-sensor-01",
        )
        return {
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
        }

    def _persist_setup_state(
        self,
        tui_settings: dict[str, Any],
        *,
        status_message: str | None = None,
    ) -> None:
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        app.tui_config = tui_settings
        app.config_path = persist_tui_settings(
            PROJECT_ROOT, app.config_path, app.tui_config
        )
        app.saved_settings = load_saved_tui_settings(app.config_path)
        app.app_state.push_log(f"[System] Saved config to {app.config_path.name}")
        if status_message:
            self.query_one("#quick-setup-status", Label).update(status_message)

    def _apply_settings_to_inputs(self, settings: dict[str, Any]) -> None:
        self.query_one("#input-sensor-id", Input).value = str(settings["sensor_id"])
        self.query_one("#input-iface", Input).value = str(settings["interface"])
        self.query_one("#input-pcap", Input).value = str(settings["pcap_path"])
        self.query_one("#input-controller-url", Input).value = str(
            settings["controller_url"]
        )
        self.query_one("#input-admin-token", Input).value = str(
            settings.get("admin_token", "")
        )
        self.query_one("#input-geo-x", Input).value = str(settings["geo_sensor_x_m"])
        self.query_one("#input-geo-y", Input).value = str(settings["geo_sensor_y_m"])
        self.query_one("#chk-ml", Checkbox).value = bool(settings["ml_enabled"])
        self.query_one("#chk-geo", Checkbox).value = bool(settings["geo_enabled"])
        self.query_one("#chk-anon", Checkbox).value = bool(settings["anonymize"])
        self.query_one("#mode-live", RadioButton).value = settings["mode"] == "live"
        self.query_one("#mode-mock", RadioButton).value = settings["mode"] == "mock"
        self.query_one("#mode-pcap", RadioButton).value = settings["mode"] == "pcap"
        self._sync_dynamic_rows()

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
        app = self.app
        assert isinstance(app, SentinelTUIApp)
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
        app = self.app
        assert isinstance(app, SentinelTUIApp)
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
        self._persist_setup_state(
            settings,
            status_message=(
                f"[green]Generated token/keys via {token_source} and updated "
                f"{env_path.name}.[/green]"
            ),
        )
        self._refresh_preflight()

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
            return

        err_label.update("")  # Clear errors

        # Push config into app state
        app = self.app
        assert isinstance(app, SentinelTUIApp)
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
        config.api.upload_url = build_upload_url(cfg.get("controller_url"))
        config.ml.enabled = bool(cfg.get("ml_enabled"))
        config.geo.enabled = bool(cfg.get("geo_enabled"))
        config.geo.sensor_x_m = parse_geo_coordinate(cfg.get("geo_sensor_x_m"))
        config.geo.sensor_y_m = parse_geo_coordinate(cfg.get("geo_sensor_y_m"))
        config.privacy.anonymize_ssid = bool(cfg.get("anonymize"))

        return config

    @staticmethod
    def _apply_raw_config(config: Config, data: dict[str, Any]) -> None:
        """Apply a minimal YAML/JSON mapping onto the runtime Config object."""
        section_map = {
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
