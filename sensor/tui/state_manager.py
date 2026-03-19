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
        self._known_networks: set[str] = set()
        self._security_by_bssid: dict[str, str] = {}

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

    def reset_session(self, mode: str, sensor_id: str, interface: str) -> None:
        """Reset runtime state before a new sensor session starts."""
        with self._lock:
            self.running = False
            self.mode = mode
            self.sensor_id = sensor_id
            self.interface = interface
            self.channel_current = "—"
            self.start_time = None
            self.total_networks = 0
            self.total_frames = 0
            self.sec_open = 0
            self.sec_wep = 0
            self.sec_wpa2 = 0
            self.sec_wpa3 = 0
            self.spool_queued = 0
            self.spool_inflight = 0
            self.spool_dropped = 0
            self.cpu_percent = 0.0
            self.mem_percent = 0.0
            self.usb_status = "—"
            self._known_networks.clear()
            self._security_by_bssid.clear()
            self._drain_queue(self.log_queue)
            self._drain_queue(self.alert_queue)
            self._drain_queue(self.network_queue)

    def update_spool(self, stats: dict[str, Any]) -> None:
        with self._lock:
            self.spool_queued = stats.get("queued", 0)
            self.spool_inflight = stats.get("inflight", 0)
            self.spool_dropped = stats.get("dropped", self.spool_dropped)

    def update_from_status(self, status: dict[str, Any]) -> None:
        """Synchronize TUI counters from the live controller status."""
        queue_stats = status.get("queue", {})
        usb_status = status.get("usb_watchdog", {})
        current_channel = status.get("current_channel")

        with self._lock:
            self.running = status.get("running", self.running)
            self.interface = status.get("interface", self.interface)
            self.channel_current = (
                f"Ch {current_channel}" if current_channel not in (None, 0) else "—"
            )
            self.spool_queued = queue_stats.get("queued", self.spool_queued)
            self.spool_inflight = queue_stats.get("inflight", self.spool_inflight)
            self.spool_dropped = queue_stats.get("dropped", self.spool_dropped)
            if usb_status:
                if usb_status.get("connected"):
                    suffix = (
                        " (monitor)"
                        if usb_status.get("in_monitor_mode")
                        else " (managed)"
                    )
                    self.usb_status = f"Connected{suffix}"
                else:
                    self.usb_status = "Disconnected"

    def record_network(self, net: NetworkEntry) -> None:
        """Track a live network update and refresh derived counters."""
        security = self._normalize_security(net.security)
        with self._lock:
            self.total_frames += 1
            if net.bssid:
                if net.bssid not in self._known_networks:
                    self._known_networks.add(net.bssid)
                    self.total_networks = len(self._known_networks)

                previous = self._security_by_bssid.get(net.bssid)
                if previous != security:
                    if previous:
                        self._decrement_security(previous)
                    self._security_by_bssid[net.bssid] = security
                    self._increment_security(security)

        self.push_network(net)

    def record_alert(self, alert: AlertEntry) -> None:
        """Public helper for symmetry with record_network."""
        self.push_alert(alert)

    def update_resources(self) -> None:
        """Update CPU/RAM from psutil if available."""
        try:
            import psutil

            self.cpu_percent = psutil.cpu_percent(interval=0)
            self.mem_percent = psutil.virtual_memory().percent
        except ImportError:
            pass

    @staticmethod
    def _drain_queue(target_queue: queue.Queue[Any]) -> None:
        while True:
            try:
                target_queue.get_nowait()
            except queue.Empty:
                break

    @staticmethod
    def _normalize_security(security: str | None) -> str:
        sec = (security or "unknown").upper()
        if "OPEN" in sec:
            return "OPEN"
        if "WEP" in sec:
            return "WEP"
        if "WPA3" in sec:
            return "WPA3"
        if "WPA2" in sec or "WPA" in sec:
            return "WPA2"
        return "UNKNOWN"

    def _increment_security(self, security: str) -> None:
        if security == "OPEN":
            self.sec_open += 1
        elif security == "WEP":
            self.sec_wep += 1
        elif security == "WPA3":
            self.sec_wpa3 += 1
        elif security == "WPA2":
            self.sec_wpa2 += 1

    def _decrement_security(self, security: str) -> None:
        if security == "OPEN" and self.sec_open > 0:
            self.sec_open -= 1
        elif security == "WEP" and self.sec_wep > 0:
            self.sec_wep -= 1
        elif security == "WPA3" and self.sec_wpa3 > 0:
            self.sec_wpa3 -= 1
        elif security == "WPA2" and self.sec_wpa2 > 0:
            self.sec_wpa2 -= 1


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
        except Exception:  # noqa: S110
            pass
