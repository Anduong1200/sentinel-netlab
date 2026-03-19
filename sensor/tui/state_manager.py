"""
Sentinel NetLab TUI - State Manager
Shared state between SensorController worker thread and the TUI rendering thread.
Uses thread-safe Queues and atomic counters.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class NetworkEntry:
    """A single detected network for display."""

    timestamp: str
    bssid: str
    ssid: str
    rssi: int | None
    channel: int | None
    security: str


@dataclass
class AlertEntry:
    """A single alert for display."""

    timestamp: str
    severity: str
    title: str
    description: str


class AppState:
    """
    Thread-safe shared state between the Sensor Worker and TUI.
    The sensor thread WRITES, the TUI thread READS.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Sensor status
        self.running = False
        self.mode = "idle"  # idle, live, mock, pcap
        self.sensor_id = "—"
        self.interface = "—"
        self.channel_current = "—"
        self.start_time: float | None = None

        # Stats (atomic-ish via lock)
        self.total_networks = 0
        self.total_frames = 0

        # Security posture
        self.sec_open = 0
        self.sec_wep = 0
        self.sec_wpa2 = 0
        self.sec_wpa3 = 0

        # Spool
        self.spool_queued = 0
        self.spool_inflight = 0
        self.spool_dropped = 0

        # System resources
        self.cpu_percent = 0.0
        self.mem_percent = 0.0
        self.usb_status = "—"

        # Queues for streaming data to TUI
        self.log_queue: queue.Queue[str] = queue.Queue(maxsize=500)
        self.alert_queue: queue.Queue[AlertEntry] = queue.Queue(maxsize=200)
        self.network_queue: queue.Queue[NetworkEntry] = queue.Queue(maxsize=100)

    @property
    def uptime(self) -> str:
        if self.start_time is None:
            return "—"
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        hrs, mins = divmod(mins, 60)
        return f"{hrs:02d}:{mins:02d}:{secs:02d}"

    def push_log(self, message: str) -> None:
        try:
            self.log_queue.put_nowait(message)
        except queue.Full:
            try:
                self.log_queue.get_nowait()
                self.log_queue.put_nowait(message)
            except queue.Empty:
                pass

    def push_alert(self, alert: AlertEntry) -> None:
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            try:
                self.alert_queue.get_nowait()
                self.alert_queue.put_nowait(alert)
            except queue.Empty:
                pass

    def push_network(self, net: NetworkEntry) -> None:
        try:
            self.network_queue.put_nowait(net)
        except queue.Full:
            try:
                self.network_queue.get_nowait()
                self.network_queue.put_nowait(net)
            except queue.Empty:
                pass

    def update_spool(self, stats: dict[str, Any]) -> None:
        with self._lock:
            self.spool_queued = stats.get("queued", 0)
            self.spool_inflight = stats.get("inflight", 0)

    def update_resources(self) -> None:
        """Update CPU/RAM from psutil if available."""
        try:
            import psutil

            self.cpu_percent = psutil.cpu_percent(interval=0)
            self.mem_percent = psutil.virtual_memory().percent
        except ImportError:
            pass


# ─── TUI Log Handler ─────────────────────────────────────────────────────
class TUILogHandler(logging.Handler):
    """Custom logging handler that pushes log records into the AppState queue."""

    def __init__(self, state: AppState):
        super().__init__()
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            msg = f"[{ts}] [{record.levelname}] {record.name}: {record.getMessage()}"
            self.state.push_log(msg)
        except Exception as e:
            logging.debug(f"Error pushing log to state: {e}")
