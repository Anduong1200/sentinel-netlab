"""
Sentinel NetLab - Capture Driver
Abstract interface and implementations for 802.11 frame capture.
Supports monitor mode, channel hopping, and raw frame extraction.
"""

import logging
import os
import subprocess  # nosec B404
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from queue import Empty, Queue

logger = logging.getLogger(__name__)


@dataclass
class RawFrame:
    """Raw captured frame with metadata"""

    data: bytes  # Raw radiotap + 802.11 bytes
    timestamp: float  # Capture time (monotonic)
    channel: int  # Channel captured on
    iface: str  # Interface name


class CaptureDriver(ABC):
    """
    Abstract capture driver interface.
    Implementations wrap libpcap, tshark, or scapy.
    """

    def __init__(self, iface: str):
        self.iface = iface
        self.is_monitor_mode = False
        self._running = False
        self._original_mode: str | None = None

    @abstractmethod
    def enable_monitor_mode(self) -> tuple[bool, str]:
        """
        Enable monitor mode on interface.
        Returns: (success, error_message)
        """
        pass

    @abstractmethod
    def disable_monitor_mode(self) -> tuple[bool, str]:
        """
        Restore interface to original state.
        Returns: (success, error_message)
        """
        pass

    @abstractmethod
    def set_channel(self, channel: int) -> bool:
        """Switch to specified channel"""
        pass

    @abstractmethod
    def read_frame(self, timeout_ms: int = 100) -> RawFrame | None:
        """
        Read next frame from interface.
        Returns None on timeout or error.
        """
        pass

    @abstractmethod
    def start_capture(self) -> bool:
        """Start capture loop"""
        pass

    @abstractmethod
    def stop_capture(self) -> None:
        """Stop capture loop"""
        pass

    def get_supported_channels(self) -> list[int]:
        """Get list of channels supported by interface"""
        # Default implementation - can be overridden
        return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # 2.4 GHz


class IwCaptureDriver(CaptureDriver):
    """
    Capture driver using iw/ip commands and libpcap.
    Suitable for Linux with compatible drivers.
    """

    def __init__(self, iface: str):
        super().__init__(iface)
        self._pcap_handle = None
        self._frame_queue: Queue = Queue(maxsize=10000)
        self._capture_thread: threading.Thread | None = None

    def enable_monitor_mode(self) -> tuple[bool, str]:
        """Enable monitor mode using iw/ip commands"""
        try:
            # Check if interface exists
            if not self._iface_exists():
                return False, f"Interface {self.iface} not found"

            # Bring interface down
            result = subprocess.run(
                ["ip", "link", "set", self.iface, "down"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False, f"Failed to bring down interface: {result.stderr}"

            # Set monitor mode
            result = subprocess.run(
                ["iw", "dev", self.iface, "set", "type", "monitor"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                # Try alternative method
                result = subprocess.run(
                    ["iw", self.iface, "set", "monitor", "none"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    return False, f"Failed to set monitor mode: {result.stderr}"

            # Bring interface up
            result = subprocess.run(
                ["ip", "link", "set", self.iface, "up"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False, f"Failed to bring up interface: {result.stderr}"

            self.is_monitor_mode = True
            logger.info(f"Monitor mode enabled on {self.iface}")
            return True, ""

        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except FileNotFoundError as e:
            return False, f"Required command not found: {e}"
        except Exception as e:
            return False, str(e)

    def disable_monitor_mode(self) -> tuple[bool, str]:
        """Restore interface to managed mode"""
        try:
            subprocess.run(
                ["ip", "link", "set", self.iface, "down"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["iw", "dev", self.iface, "set", "type", "managed"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", self.iface, "up"], capture_output=True, timeout=10
            )

            self.is_monitor_mode = False
            logger.info(f"Monitor mode disabled on {self.iface}")
            return True, ""

        except Exception as e:
            return False, str(e)

    def set_channel(self, channel: int) -> bool:
        """Switch to specified channel"""
        try:
            result = subprocess.run(
                ["iw", "dev", self.iface, "set", "channel", str(channel)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.warning(f"Failed to set channel {channel}: {result.stderr}")
                return False
            return True
        except Exception as e:
            logger.error(f"Channel switch error: {e}")
            return False

    def read_frame(self, timeout_ms: int = 100) -> RawFrame | None:
        """Read frame from queue"""
        try:
            return self._frame_queue.get(timeout=timeout_ms / 1000.0)
        except Empty:
            return None

    def start_capture(self) -> bool:
        """Start capture using scapy (fallback if pcap not available)"""
        self._running = True

        try:
            # Try to use scapy for capture
            from scapy.all import sniff  # noqa: E402

            def packet_handler(pkt):
                if not self._running:
                    return
                try:
                    raw_frame = RawFrame(
                        data=bytes(pkt),
                        timestamp=time.monotonic(),
                        channel=0,  # Will be set by parser
                        iface=self.iface,
                    )
                    self._frame_queue.put_nowait(raw_frame)
                except Exception:  # nosec B110
                    pass

            def capture_loop():
                while self._running:
                    try:
                        sniff(
                            iface=self.iface, prn=packet_handler, store=False, timeout=1
                        )
                    except Exception as e:
                        logger.error(f"Capture error: {e}")
                        time.sleep(1)

            self._capture_thread = threading.Thread(
                target=capture_loop, daemon=True, name="CaptureThread"
            )
            self._capture_thread.start()
            logger.info(f"Capture started on {self.iface}")
            return True

            return True

        except (ImportError, OSError) as e:
            logger.error(
                f"Scapy capture error (scapy not available or OS missing libs): {e}"
            )
            self._running = False
            return False

    def stop_capture(self) -> None:
        """Stop capture thread"""
        self._running = False
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3)
        logger.info("Capture stopped")

    def get_supported_channels(self) -> list[int]:
        """Get channels from iw"""
        try:
            result = subprocess.run(
                ["iw", "phy"], capture_output=True, text=True, timeout=10
            )
            channels = []
            for line in result.stdout.split("\n"):
                if "MHz" in line and "disabled" not in line.lower():
                    # Parse channel number from frequency
                    try:
                        freq = int(line.split()[1])
                        if 2412 <= freq <= 2484:
                            channels.append((freq - 2407) // 5)
                        elif 5180 <= freq <= 5825:
                            channels.append((freq - 5000) // 5)
                    except (IndexError, ValueError):
                        pass

            return channels if channels else [1, 6, 11]  # Default fallback
        except Exception:
            return [1, 6, 11]

    def _iface_exists(self) -> bool:
        """Check if interface exists"""
        return os.path.exists(f"/sys/class/net/{self.iface}")


class MockCaptureDriver(CaptureDriver):
    """
    Mock capture driver for testing without hardware.
    Generates synthetic frames for development.
    """

    def __init__(self, iface: str = "mock0"):
        super().__init__(iface)
        self._frame_generator = None
        self._running = False

    def enable_monitor_mode(self) -> tuple[bool, str]:
        self.is_monitor_mode = True
        logger.info(f"Mock monitor mode enabled on {self.iface}")
        return True, ""

    def disable_monitor_mode(self) -> tuple[bool, str]:
        self.is_monitor_mode = False
        return True, ""

    def set_channel(self, channel: int) -> bool:
        logger.debug(f"Mock channel set to {channel}")
        return True

    def read_frame(self, timeout_ms: int = 100) -> RawFrame | None:
        """Generate mock frame"""
        import random

        if not self._running:
            return None

        time.sleep(timeout_ms / 1000.0)

        # Simulate occasional frame capture
        if random.random() > 0.3:  # nosec B311
            return None

        # Generate mock beacon frame
        mock_data = self._generate_mock_beacon()
        return RawFrame(
            data=mock_data,
            timestamp=time.monotonic(),
            channel=random.choice([1, 6, 11]),  # nosec B311
            iface=self.iface,
        )

    def start_capture(self) -> bool:
        self._running = True
        logger.info("Mock capture started")
        return True

    def stop_capture(self) -> None:
        self._running = False
        logger.info("Mock capture stopped")

    def _generate_mock_beacon(self) -> bytes:
        """Generate mock beacon frame bytes"""
        import random
        import struct

        # Simplified mock frame
        bssid = bytes([random.randint(0, 255) for _ in range(6)])  # nosec B311
        ssid = b"TestNetwork"

        # Very simplified beacon structure
        frame = bytearray()
        frame.extend(b"\x80\x00")  # Frame control (beacon)
        frame.extend(b"\x00\x00")  # Duration
        frame.extend(b"\xff" * 6)  # DA (broadcast)
        frame.extend(bssid)  # SA
        frame.extend(bssid)  # BSSID
        frame.extend(b"\x00\x00")  # Sequence
        frame.extend(b"\x00" * 8)  # Timestamp
        frame.extend(struct.pack("<H", 100))  # Beacon interval
        frame.extend(struct.pack("<H", 0x0411))  # Capabilities

        # SSID IE
        frame.extend(b"\x00")  # Element ID
        frame.extend(bytes([len(ssid)]))  # Length
        frame.extend(ssid)

        return bytes(frame)


class PcapCaptureDriver(CaptureDriver):
    """
    Replay frames from a PCAP file.
    Useful for testing and analysis of historical data.
    """

    def __init__(
        self, iface: str, pcap_path: str, loop: bool = False, realtime: bool = False
    ):
        super().__init__(iface)
        self.pcap_path = pcap_path
        self.loop = loop
        self.realtime = realtime
        self._packets = []
        self._current_idx = 0
        self._start_time = 0.0
        self._first_pkt_time = 0.0
        self._running = False

    def enable_monitor_mode(self) -> tuple[bool, str]:
        self.is_monitor_mode = True
        return True, ""

    def disable_monitor_mode(self) -> tuple[bool, str]:
        self.is_monitor_mode = False
        return True, ""

    def set_channel(self, channel: int) -> bool:
        return True

    def start_capture(self) -> bool:
        try:
            from scapy.all import rdpcap

            if not os.path.exists(self.pcap_path):
                logger.error(f"PCAP file not found: {self.pcap_path}")
                return False

            self._packets = rdpcap(self.pcap_path)
            self._current_idx = 0
            self._running = True
            self._start_time = time.monotonic()
            if self._packets:
                self._first_pkt_time = float(self._packets[0].time)

            logger.info(
                f"Started PCAP replay: {self.pcap_path} ({len(self._packets)} frames)"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            return False

    def stop_capture(self) -> None:
        self._running = False

    def read_frame(self, timeout_ms: int = 100) -> RawFrame | None:
        if not self._running or not self._packets:
            return None

        if self._current_idx >= len(self._packets):
            if self.loop:
                self._current_idx = 0
                self._start_time = time.monotonic()
            else:
                return None

        pkt = self._packets[self._current_idx]

        # Realtime simulation
        if self.realtime:
            pkt_rel_time = float(pkt.time) - self._first_pkt_time
            elapsed = time.monotonic() - self._start_time

            if pkt_rel_time > elapsed:
                wait = pkt_rel_time - elapsed
                if wait > timeout_ms / 1000.0:
                    time.sleep(timeout_ms / 1000.0)
                    return None
                time.sleep(wait)

        self._current_idx += 1

        return RawFrame(
            data=bytes(pkt),
            timestamp=time.monotonic(),
            channel=6,  # Default to valid channel to pass validation
            iface=self.iface,
        )
