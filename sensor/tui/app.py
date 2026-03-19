"""
Sentinel NetLab TUI - Main Application
Entry point: python -m sensor.tui
"""

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
from textual.screen import Screen
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
    Static,
)

from sensor.tui.state_manager import AlertEntry, AppState, NetworkEntry, TUILogHandler

# ─── Constants ───────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
REFRESH_INTERVAL = 0.8  # seconds


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 1: SETUP & CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
class SetupScreen(Screen):
    """Configuration screen to choose operation mode and options."""

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

                # Mode Selection
                with Container(classes="setup-group"):
                    yield Label("⚡ OPERATION MODE", classes="setup-group-title")
                    with RadioSet(id="mode-select"):
                        yield RadioButton("Live Combat (Thực chiến)", id="mode-live")
                        yield RadioButton(
                            "Mock / Test Mode", id="mode-mock", value=True
                        )
                        yield RadioButton("PCAP Replay", id="mode-pcap")

                # Interface
                with Container(classes="setup-group"):
                    yield Label("🔌 CONFIGURATION", classes="setup-group-title")
                    yield Label("Interface:")
                    yield Input(
                        value="wlan0mon",
                        placeholder="Enter WiFi interface",
                        id="input-iface",
                    )
                    yield Label("PCAP Path (for Replay):")
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
                        "Anonymize MAC/SSID", id="chk-anon", value=True
                    )

                yield Button(
                    "▶  START SENSOR  (F5)",
                    id="btn-start",
                    variant="success",
                )

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.action_start_sensor()

    def action_start_sensor(self) -> None:
        """Gather config and switch to Dashboard."""
        # Determine mode
        radio_set = self.query_one("#mode-select", RadioSet)
        mode = "mock"  # default
        if self.query_one("#mode-live", RadioButton).value:
            mode = "live"
        elif self.query_one("#mode-pcap", RadioButton).value:
            mode = "pcap"

        iface = self.query_one("#input-iface", Input).value or "mock0"
        pcap_path = self.query_one("#input-pcap", Input).value
        ml_enabled = self.query_one("#chk-ml", Checkbox).value
        geo_enabled = self.query_one("#chk-geo", Checkbox).value
        anonymize = self.query_one("#chk-anon", Checkbox).value

        # Push config into app state
        app: SentinelTUIApp = self.app  # type: ignore
        state = app.app_state
        state.mode = mode
        state.interface = iface if mode == "live" else "mock0"
        state.sensor_id = os.environ.get("SENSOR_ID", "tui-sensor-01")

        # Store extra config for the worker
        app.tui_config = {
            "mode": mode,
            "interface": iface if mode == "live" else "mock0",
            "pcap_path": pcap_path,
            "ml_enabled": ml_enabled,
            "geo_enabled": geo_enabled,
            "anonymize": anonymize,
        }

        # Switch to dashboard
        app.push_screen("dashboard")
        app.start_sensor_worker()


# ═══════════════════════════════════════════════════════════════════════════════
# SCREEN 2: LIVE DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
class DashboardScreen(Screen):
    """Real-time monitoring dashboard with 4 panels."""

    BINDINGS = [
        Binding("f1", "show_setup", "Setup"),
        Binding("space", "toggle_pause", "Pause Log"),
        Binding("q", "quit_app", "Quit"),
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
                    yield Label(
                        "[b]📶  LIVE NETWORK FEED[/b]", classes="panel-title"
                    )
                    table = DataTable(id="net-table")
                    table.cursor_type = "row"
                    table.zebra_stripes = True
                    yield table

                with Container(id="alert-panel"):
                    yield Label(
                        "[b]🚨  THREAT ALERTS[/b]", classes="panel-title"
                    )
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
        app: SentinelTUIApp = self.app  # type: ignore
        app.log_paused = not app.log_paused

    def action_quit_app(self) -> None:
        self.app.exit()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════
class SentinelTUIApp(App):
    """Sentinel NetLab – Multi-Screen Terminal Dashboard."""

    TITLE = "Sentinel NetLab"
    SUB_TITLE = "Terminal Control Panel"
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

    def on_mount(self) -> None:
        # Show setup screen first
        self.push_screen("setup")

        # Start the periodic TUI updater
        self.set_interval(REFRESH_INTERVAL, self._update_dashboard)

    def start_sensor_worker(self) -> None:
        """Launch the SensorController in a background thread."""
        if self._sensor_thread and self._sensor_thread.is_alive():
            return

        self._stop_event.clear()
        self.app_state.running = True
        self.app_state.start_time = time.time()

        # Install log handler to capture sensor logs into TUI
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

            # Build CLI args
            args = [
                "python3", str(PROJECT_ROOT / "sensor" / "cli.py"),
                "--sensor-id", self.app_state.sensor_id,
            ]

            if mode == "mock":
                os.environ["SENSOR_MOCK_MODE"] = "true"
                args.extend(["--config-file", "config.yaml"])
            elif mode == "live":
                os.environ.setdefault("SENSOR_INTERFACE", cfg.get("interface", "wlan0mon"))
                args.extend(["--config-file", "config.yaml"])
            elif mode == "pcap":
                pcap = cfg.get("pcap_path", "")
                if pcap:
                    args.extend(["--pcap", pcap])

            self.app_state.push_log(f"[System] Launching: {' '.join(args)}")

            # Run as subprocess so it doesn't crash the TUI
            proc = subprocess.Popen(
                args,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            # Stream output to log queue
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

        except Exception as e:
            self.app_state.push_log(f"[Error] Sensor worker failed: {e}")
        finally:
            self.app_state.running = False

    def _update_dashboard(self) -> None:
        """Periodic callback to refresh the Dashboard screen."""
        # Only update if dashboard is active
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
                f"USB:    [green]{state.interface}[/green]" if state.running else "USB:    [yellow]Idle[/yellow]"
            )
            screen.query_one("#sys-uptime", Label).update(
                f"Uptime: [dim]{state.uptime}[/dim]"
            )

            # Spool
            screen.query_one("#spool-queued", Label).update(
                f"Queued:   {state.spool_queued}"
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

            # Sensor info
            screen.query_one("#sen-id", Label).update(
                f"ID:    [cyan]{state.sensor_id}[/cyan]"
            )
            screen.query_one("#sen-mode", Label).update(
                f"Mode:  [{'green' if state.running else 'yellow'}]{state.mode.upper()}[/]"
            )
            screen.query_one("#sen-iface", Label).update(
                f"Iface: {state.interface}"
            )
            screen.query_one("#sen-nets", Label).update(
                f"Nets:  [cyan]{state.total_networks}[/cyan]"
            )
        except Exception:
            pass

        # ── Drain network queue into table ──
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
                        net.timestamp, net.bssid, net.ssid,
                        rssi_display, str(net.channel or "—"), sec_display,
                    )
                    drained += 1
                except queue.Empty:
                    break

            # Keep table manageable
            while table.row_count > 50:
                table.remove_row(table.rows[next(iter(table.rows))])
        except Exception:
            pass

        # ── Drain alert queue ──
        try:
            alert_log = screen.query_one("#alert-log", RichLog)
            while True:
                try:
                    alert = state.alert_queue.get_nowait()
                    sev_color = {
                        "Critical": "bold white on red",
                        "High": "bold red",
                        "Medium": "yellow",
                        "Low": "cyan",
                    }.get(alert.severity, "white")

                    alert_log.write(
                        Text.from_markup(
                            f"[dim]{alert.timestamp}[/dim] [{sev_color}]🚨 {alert.severity.upper()}[/{sev_color}] "
                            f"{alert.title}: {alert.description[:80]}"
                        )
                    )
                except queue.Empty:
                    break
        except Exception:
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
            except Exception:
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
