"""
Sentinel NetLab - GPS Components
Consolidated GPS reading logic to avoid duplication between `wardrive.py` and other modules.
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class GPSFix:
    """GPS position data"""

    lat: float
    lon: float
    alt: float | None = None
    speed: float | None = None
    accuracy_m: float | None = None
    timestamp: str | None = None

    @classmethod
    def mock(cls) -> "GPSFix":
        """Generate mock GPS fix for testing"""
        import random

        return cls(
            lat=21.0285 + random.uniform(-0.01, 0.01),  # noqa: S311
            lon=105.8542 + random.uniform(-0.01, 0.01),  # noqa: S311
            alt=10.0,
            speed=5.0,
            accuracy_m=3.0,
            timestamp=datetime.now(UTC).isoformat(),
        )


class GPSReader:
    """Read GPS data from serial device or gpsd"""

    def __init__(self, device: str | None = None, mock: bool = False):
        self.device = device
        self.mock = mock
        self._last_fix: GPSFix | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def get_fix(self) -> GPSFix | None:
        """Get current GPS fix"""
        if self.mock:
            self._last_fix = GPSFix.mock()
            return self._last_fix
        return self._last_fix

    def start(self):
        """Start GPS reading"""
        if self.mock:
            logger.info("GPS: Using mock mode")
        elif self.device:
            logger.info(f"GPS: Connecting to {self.device}")
            self._running = True
            self._thread = threading.Thread(target=self._read_serial, daemon=True)
            self._thread.start()
        else:
            logger.warning("GPS: No device specified, using null")

    def stop(self):
        """Stop GPS reading"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _read_serial(self):
        """Read NMEA data from serial port"""
        try:
            import pynmea2
            import serial
        except ImportError:
            logger.error("Missing dependencies: pip install pyserial pynmea2")
            return

        try:
            with serial.Serial(self.device, 9600, timeout=1) as ser:
                while self._running:
                    try:
                        line = ser.readline().decode("ascii", errors="replace").strip()
                        if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                            msg = pynmea2.parse(line)
                            if msg.lat and msg.lon:
                                self._last_fix = GPSFix(
                                    lat=msg.latitude,
                                    lon=msg.longitude,
                                    alt=msg.altitude,
                                    speed=0.0,
                                    accuracy_m=(
                                        float(msg.horizontal_dil)
                                        if msg.horizontal_dil
                                        else 5.0
                                    ),
                                    timestamp=datetime.now(UTC).isoformat(),
                                )
                    except Exception as e:
                        logger.debug(f"GPS parse error: {e}")
                        continue
        except Exception as e:
            logger.error(f"GPS Error: {e}")
            time.sleep(1)
