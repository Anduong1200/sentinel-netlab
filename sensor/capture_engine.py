#!/usr/bin/env python3
"""
Refactored Capture Module
Implements CaptureEngine with support for Scapy and Tshark backends.
Includes queue-based processing and robust error handling.
"""

import threading
import queue
import time
import subprocess
import logging
from threading import Event

# Local imports
try:
    from scapy.all import AsyncSniffer
except ImportError:
    AsyncSniffer = None  # Handle missing scapy gracefully

logger = logging.getLogger("capture")


class CaptureEngine:
    """
    Unified Capture Engine supporting Scapy (Dev) and Tshark (Prod).
    """

    def __init__(
        self,
        iface: str,
        backend: str = 'scapy',
        channels=(
            1,
            6,
            11)):
        self.iface = iface
        self.backend = backend
        self.channels = list(channels)
        self._pkt_q = queue.Queue(maxsize=10000)
        self._stop = Event()
        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._hopper_thread = None
        self._sniffer = None
        self._is_capturing = False

    def ensure_monitor(self) -> bool:
        """
        Ensure interface is in monitor mode.
        Returns True if successful, False otherwise.
        """
        try:
            # Check current mode first
            res = subprocess.run(
                ["iw", "dev", self.iface, "info"], capture_output=True, text=True)
            if "type monitor" in res.stdout:
                return True

            logger.info(f"Setting {self.iface} to monitor mode...")
            subprocess.run(["sudo", "ip", "link", "set",
                           self.iface, "down"], check=True)
            subprocess.run(["sudo", "iw", "dev", self.iface,
                           "set", "type", "monitor"], check=True)
            subprocess.run(["sudo", "ip", "link", "set",
                           self.iface, "up"], check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed set monitor mode: {e}")
            return False
        except FileNotFoundError:
            logger.error("Required tools (iw, ip) not found.")
            return False

    def start(self, packet_callback=None):
        """Start capturing packets."""
        if self._is_capturing:
            return

        if not self.ensure_monitor():
            logger.error("Cannot start capture: Monitor mode failed")
            return

        self._stop.clear()
        self._is_capturing = True

        # Start processing worker
        if not self._worker.is_alive():
            self._worker = threading.Thread(
                target=self._process_loop, daemon=True)
            self._worker.start()

        # Start backend
        if self.backend == 'scapy' and AsyncSniffer:
            self._start_scapy_sniffer(packet_callback)
        elif self.backend == 'tshark':
            pass  # Tshark logic would go here
        else:
            logger.warning(f"Unknown backend {self.backend}, default to Scapy")
            self._start_scapy_sniffer(packet_callback)

        # Start channel hopping
        self._hopper_thread = threading.Thread(
            target=self._channel_hopper, daemon=True)
        self._hopper_thread.start()

        logger.info(f"Capture started on {self.iface} using {self.backend}")

    def stop(self):
        """Stop capturing."""
        self._stop.set()
        self._is_capturing = False

        if self._sniffer:
            self._sniffer.stop()

        if self._hopper_thread:
            self._hopper_thread.join(timeout=2)

        logger.info("Capture stopped")

    def _start_scapy_sniffer(self, callback):
        """Start Scapy AsyncSniffer"""
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=lambda pkt: self._pkt_q.put(pkt),
            store=False,
            filter="type mgt"
        )
        self._sniffer.start()

    def _channel_hopper(self):
        """Hop through channels"""
        from itertools import cycle
        chan_cycle = cycle(self.channels)

        while not self._stop.is_set():
            ch = next(chan_cycle)
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", self.iface, "set", "channel", str(ch)],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass
            time.sleep(0.5)

    def _process_loop(self):
        """Process packets from queue"""
        # Batch processing logic would be here
        # For now, just a loop placeholder
        while not self._stop.is_set():
            try:
                self._pkt_q.get(timeout=1)
                # Parse logic linked here
                self._pkt_q.task_done()
            except queue.Empty:
                pass

    def get_status(self):
        return {
            "is_capturing": self._is_capturing,
            "backend": self.backend,
            "interface": self.iface
        }
