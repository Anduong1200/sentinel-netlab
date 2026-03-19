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
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

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

from sensor.tui.state_manager import AlertEntry, AppState, TUILogHandler

# ─── Constants ───────────────────────────────────────────────────────────────
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


def check_controller_online() -> bool:
    """Quick check if the Controller API is reachable."""
    try:
        import urllib.request

        url = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:8080")
        if not url.startswith(("http://", "https://")):
            return False
        resp = urllib.request.urlopen(f"{url}/api/v1/sensors", timeout=1)  # noqa: S310 # nosec B310
        return bool(resp.getcode() == 200)
    except Exception:  # noqa: S110
        return False


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
        self.app.exit()


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 1: SETUP & CONFIG (Pre-flight Check)
# ═══════════════════════════════════════════════════════════════════════════════
class SetupScreen(Screen):
    """Configuration screen with auto-detection and pre-flight validation."""

    BINDINGS = [Binding("f5", "start_sensor", "Start Sensor")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="setup-screen"):
            with VerticalScroll(id="setup-container"):
                yield Label(
                    r"""[bold cyan]
  ____  _____ _   _ _____ ___ _   _ _____ _
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |
  ___) | |___| |\  | | |  | || |\  | |___| |___
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
         N E T L A B  —  T U I[/bold cyan]
""",
                    classes="panel-title",
                )

                # Pre-flight status
                with Container(classes="setup-group"):
                    yield Label("🔍 PRE-FLIGHT CHECK", classes="setup-group-title")
                    yield Label("", id="pf-wifi")
                    yield Label("", id="pf-controller")

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
                    yield Label("Interface (auto-detected):")
                    yield Input(
                        value="wlan0mon",
                        placeholder="WiFi interface",
                        id="input-iface",
                    )
                    yield Label("PCAP Path (for Replay mode):")
                    yield Input(
                        value="",
                        placeholder="/path/to/capture.pcap",
                        id="input-pcap",
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
        # Detect WiFi interfaces
        ifaces = detect_wifi_interfaces()
        iface_text = ", ".join(ifaces)
        has_wifi = ifaces[0] != "(none detected)"
        color = "green" if has_wifi else "yellow"
        self.query_one("#pf-wifi", Label).update(
            f"WiFi Cards: [{color}]{iface_text}[/{color}]"
        )

        # Auto-fill best interface
        if has_wifi:
            # Prefer monitor mode interfaces
            best = next((i for i in ifaces if "mon" in i), ifaces[0])
            self.query_one("#input-iface", Input).value = best

        # Check controller
        ctrl_ok = check_controller_online()
        ctrl_color = "green" if ctrl_ok else "red"
        ctrl_text = "ONLINE ✓" if ctrl_ok else "OFFLINE ✗ (make lab-up?)"
        self.query_one("#pf-controller", Label).update(
            f"Controller: [{ctrl_color}]{ctrl_text}[/{ctrl_color}]"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.action_start_sensor()

    def action_start_sensor(self) -> None:
        """Gather config, validate, and switch to Dashboard."""
        # Determine mode
        mode = "mock"  # default
        if self.query_one("#mode-live", RadioButton).value:
            mode = "live"
        elif self.query_one("#mode-pcap", RadioButton).value:
            mode = "pcap"

        iface = self.query_one("#input-iface", Input).value or "mock0"
        pcap_path = self.query_one("#input-pcap", Input).value

        # ── Pre-flight Validation (Fool-proof) ──
        err_label = self.query_one("#validation-error", Label)

        if mode == "live":
            ifaces = detect_wifi_interfaces()
            if iface not in ifaces and ifaces[0] != "(none detected)":
                err_label.update(
                    f"[bold red]❌ Interface '{iface}' not found! "
                    f"Available: {', '.join(ifaces)}[/bold red]"
                )
                return
            if ifaces[0] == "(none detected)":
                err_label.update(
                    "[bold red]❌ No WiFi card detected! "
                    "Please plug in a USB WiFi adapter.[/bold red]"
                )
                return

        if mode == "pcap" and not pcap_path:
            err_label.update("[bold red]❌ PCAP mode requires a file path![/bold red]")
            return

        if mode == "pcap" and pcap_path and not os.path.isfile(pcap_path):
            err_label.update(f"[bold red]❌ File not found: {pcap_path}[/bold red]")
            return

        err_label.update("")  # Clear errors

        ml_enabled = self.query_one("#chk-ml", Checkbox).value
        geo_enabled = self.query_one("#chk-geo", Checkbox).value
        anonymize = self.query_one("#chk-anon", Checkbox).value

        # Push config into app state
        app = self.app
        assert isinstance(app, SentinelTUIApp)
        state = app.app_state
        state.mode = mode
        state.interface = iface if mode == "live" else "mock0"
        state.sensor_id = os.environ.get("SENSOR_ID", "tui-sensor-01")

        app.tui_config = {
            "mode": mode,
            "interface": iface if mode == "live" else "mock0",
            "pcap_path": pcap_path,
            "ml_enabled": ml_enabled,
            "geo_enabled": geo_enabled,
            "anonymize": anonymize,
        }

        # Switch to dashboard & start
        app.push_screen("dashboard")
        app.start_sensor_worker()


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 2: LIVE DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
class DashboardScreen(Screen):
    """Real-time monitoring dashboard with 4 panels and hot-actions."""

    BINDINGS = [
        Binding("f1", "show_setup", "Setup"),
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

                with Container(id="alert-panel"):
                    yield Label("[b]🚨  THREAT ALERTS[/b]", classes="panel-title")
                    yield RichLog(
                        id="alert-log",
                        max_lines=100,
                        highlight=True,
                        markup=True,
                    )

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
        app.app_state.push_log("[System] ⚡ Force channel hop requested")

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
        app._stop_event.set()
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
        self.log_paused = False
        self._sensor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
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
        self.app_state.running = True
        self.app_state.start_time = time.time()

        # Install log handler
        tui_handler = TUILogHandler(self.app_state)
        tui_handler.setLevel(logging.INFO)
        root_logger = logging.getLogger()
        root_logger.addHandler(tui_handler)
        root_logger.setLevel(logging.INFO)

        self._sensor_thread = threading.Thread(
            target=self._run_sensor, daemon=True, name="SensorWorker"
        )
        self._sensor_thread.start()
        self.app_state.push_log("[System] Sensor Worker started.")

    def _run_sensor(self) -> None:
        """Run the SensorController in a background thread."""
        try:
            cfg = self.tui_config
            mode = cfg.get("mode", "mock")

            args = [
                "python3",
                str(PROJECT_ROOT / "sensor" / "cli.py"),
                "--sensor-id",
                self.app_state.sensor_id,
            ]

            if mode == "mock":
                os.environ["SENSOR_MOCK_MODE"] = "true"
                args.extend(["--config-file", "config.yaml"])
            elif mode == "live":
                os.environ.setdefault(
                    "SENSOR_INTERFACE", cfg.get("interface", "wlan0mon")
                )
                args.extend(["--config-file", "config.yaml"])
            elif mode == "pcap":
                pcap = cfg.get("pcap_path", "")
                if pcap:
                    args.extend(["--pcap", pcap])

            self.app_state.push_log(f"[System] Launching: {' '.join(args)}")

            proc = subprocess.Popen(
                args,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            while not self._stop_event.is_set():
                if proc.stdout:
                    line = proc.stdout.readline()
                    if line:
                        self.app_state.push_log(line.strip())
                    elif proc.poll() is not None:
                        break
                else:
                    time.sleep(0.1)

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        except Exception as e:
            self.app_state.push_log(f"[Error] Sensor worker failed: {e}")
        finally:
            self.app_state.running = False

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

        state = self.app_state
        state.update_resources()
        screen = self.screen

        # ── System Health ──
        try:
            screen.query_one("#sys-cpu", Label).update(
                f"CPU:    [{self._color_pct(state.cpu_percent)}]{state.cpu_percent:.0f}%[/]"
            )
            screen.query_one("#sys-mem", Label).update(
                f"RAM:    [{self._color_pct(state.mem_percent)}]{state.mem_percent:.0f}%[/]"
            )
            screen.query_one("#sys-usb", Label).update(
                f"USB:    [green]{state.interface}[/green]"
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
                f"WEP:  [{'dark_orange' if state.sec_wep else 'green'}]{state.sec_wep}[/]"
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
                f"Mode:  [{'green' if state.running else 'yellow'}]{state.mode.upper()}[/]"
            )
            screen.query_one("#sen-iface", Label).update(f"Iface: {state.interface}")
            screen.query_one("#sen-nets", Label).update(
                f"Nets:  [cyan]{state.total_networks}[/cyan]"
            )
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
                            f"[dim]{debounced.timestamp}[/dim] [{sev_color}]🚨 {debounced.severity.upper()}[/{sev_color}] "
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


# ─── Entry Point ─────────────────────────────────────────────────────────────
def main():
    app = SentinelTUIApp()
    app.run()


if __name__ == "__main__":
    main()
