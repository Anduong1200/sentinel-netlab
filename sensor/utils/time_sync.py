"""
Sentinel NetLab - Time Sync Utilities
NTP and GPS time synchronization helpers.
"""

import logging
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class TimeSync:
    """
    Time synchronization checker and manager.
    Validates NTP sync status and GPS time availability.
    """

    def __init__(self, max_drift_ms: int = 1000):
        """
        Initialize time sync checker.

        Args:
            max_drift_ms: Maximum acceptable drift in milliseconds
        """
        self.max_drift_ms = max_drift_ms
        self._last_check: Optional[datetime] = None
        self._is_synced = False
        self._sync_source: Optional[str] = None

    def check_ntp_sync(self) -> tuple[bool, str]:
        """
        Check if system is NTP synchronized.

        Returns:
            (is_synced, status_message)
        """
        try:
            # Try timedatectl (systemd)
            result = subprocess.run(
                ["timedatectl", "show", "--property=NTPSynchronized"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                if "yes" in result.stdout.lower():
                    self._is_synced = True
                    self._sync_source = "NTP"
                    return True, "NTP synchronized"
                else:
                    return False, "NTP not synchronized"
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"timedatectl check failed: {e}")

        # Try ntpq
        try:
            result = subprocess.run(
                ["ntpq", "-c", "rv"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                if "leap=00" in result.stdout or "sync" in result.stdout:
                    self._is_synced = True
                    self._sync_source = "NTP"
                    return True, "NTP synchronized (ntpq)"
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"ntpq check failed: {e}")

        # Try chronyc
        try:
            result = subprocess.run(
                ["chronyc", "tracking"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "synchronized" in result.stdout.lower():
                self._is_synced = True
                self._sync_source = "Chrony"
                return True, "Chrony synchronized"
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"chronyc check failed: {e}")

        return False, "Unable to verify NTP sync"

    def force_ntp_sync(self) -> bool:
        """
        Force NTP synchronization.

        Returns:
            True if sync succeeded
        """
        try:
            # Try ntpdate
            result = subprocess.run(
                ["ntpdate", "-u", "pool.ntp.org"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self._is_synced = True
                self._sync_source = "NTP (forced)"
                logger.info("NTP sync forced successfully")
                return True
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"ntpdate failed: {e}")

        # Try systemd
        try:
            subprocess.run(
                ["timedatectl", "set-ntp", "true"],
                capture_output=True, timeout=5
            )
            time.sleep(5)  # Wait for sync
            return self.check_ntp_sync()[0]
        except Exception as e:
            logger.warning(f"systemd NTP enable failed: {e}")

        return False

    def get_timestamp(self) -> str:
        """Get current UTC timestamp in ISO8601 format"""
        return datetime.now(timezone.utc).isoformat()

    def get_monotonic(self) -> float:
        """Get monotonic time for sequence ordering"""
        return time.monotonic()

    def is_synced(self) -> bool:
        """Check if time is synchronized"""
        return self._is_synced

    def get_sync_source(self) -> Optional[str]:
        """Get synchronization source"""
        return self._sync_source

    def get_status(self) -> dict:
        """Get time sync status"""
        return {
            'is_synced': self._is_synced,
            'sync_source': self._sync_source,
            'timestamp_utc': self.get_timestamp(),
            'monotonic': self.get_monotonic()
        }


class GPSTime:
    """
    GPS time synchronization for wardriving scenarios.
    Parses NMEA sentences for precise timestamps.
    """

    def __init__(self, device: str = "/dev/ttyUSB0", baudrate: int = 9600):
        """
        Initialize GPS time reader.

        Args:
            device: GPS serial device path
            baudrate: Serial baudrate
        """
        self.device = device
        self.baudrate = baudrate
        self._serial = None
        self._last_gps_time: Optional[datetime] = None
        self._last_position: Optional[dict] = None

    def connect(self) -> bool:
        """Connect to GPS device"""
        try:
            import serial
            self._serial = serial.Serial(
                self.device,
                self.baudrate,
                timeout=1
            )
            logger.info(f"Connected to GPS: {self.device}")
            return True
        except ImportError:
            logger.error("pyserial not installed")
            return False
        except Exception as e:
            logger.error(f"GPS connection failed: {e}")
            return False

    def read_position(self) -> Optional[dict]:
        """
        Read current GPS position.

        Returns:
            Dict with lat, lon, alt, timestamp or None
        """
        if not self._serial:
            return None

        try:
            line = self._serial.readline().decode('ascii', errors='ignore').strip()

            # Parse GPRMC or GPGGA
            if line.startswith('$GPRMC') or line.startswith('$GPGGA'):
                parts = line.split(',')
                if len(parts) >= 6:
                    # Parse latitude
                    lat_raw = parts[3] if line.startswith(
                        '$GPGGA') else parts[3]
                    lat_dir = parts[4] if line.startswith(
                        '$GPGGA') else parts[4]

                    if lat_raw and lat_dir:
                        lat = self._parse_coord(lat_raw, lat_dir)

                        # Parse longitude
                        lon_raw = parts[5] if line.startswith(
                            '$GPGGA') else parts[5]
                        lon_dir = parts[6] if line.startswith(
                            '$GPGGA') else parts[6]

                        if lon_raw and lon_dir:
                            lon = self._parse_coord(lon_raw, lon_dir)

                            self._last_position = {
                                'lat': lat, 'lon': lon, 'alt': None, 'timestamp': datetime.now(
                                    timezone.utc).isoformat()}
                            return self._last_position
        except Exception as e:
            logger.debug(f"GPS read error: {e}")

        return None

    def _parse_coord(self, value: str, direction: str) -> float:
        """Parse NMEA coordinate format"""
        try:
            if len(value) >= 4:
                if '.' in value:
                    dot_pos = value.index('.')
                    degrees = float(value[:dot_pos - 2])
                    minutes = float(value[dot_pos - 2:])
                    result = degrees + minutes / 60.0
                    if direction in ['S', 'W']:
                        result = -result
                    return result
        except Exception:
            pass
        return 0.0

    def close(self) -> None:
        """Close GPS connection"""
        if self._serial:
            self._serial.close()
            self._serial = None
