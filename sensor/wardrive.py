#!/usr/bin/env python3
"""
Sentinel NetLab - Wardriving CLI
Capture WiFi networks while mobile with GPS correlation.

Usage:
    python wardrive.py --iface wlan0 --gps /dev/ttyUSB0 --output session.json
"""

import sys
import time
import json
import signal
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GPSFix:
    """GPS position data"""
    lat: float
    lon: float
    alt: Optional[float] = None
    speed: Optional[float] = None
    accuracy_m: Optional[float] = None
    timestamp: Optional[str] = None

    @classmethod
    def mock(cls) -> 'GPSFix':
        """Generate mock GPS fix for testing"""
        import random
        return cls(
            lat=21.0285 + random.uniform(-0.01, 0.01),
            lon=105.8542 + random.uniform(-0.01, 0.01),
            alt=10.0,
            speed=5.0,
            accuracy_m=3.0,
            timestamp=datetime.now(timezone.utc).isoformat()
        )


@dataclass
class WardriveSighting:
    """Single network sighting during wardrive"""
    timestamp: str
    bssid: str
    ssid: Optional[str]
    rssi_dbm: int
    channel: int
    security: str
    gps: Optional[GPSFix]
    sensor_id: str


class GPSReader:
    """Read GPS data from serial device or gpsd"""

    def __init__(self, device: Optional[str] = None, mock: bool = False):
        self.device = device
        self.mock = mock
        self._last_fix: Optional[GPSFix] = None
        self._running = False
        self._thread = None

    def get_fix(self) -> Optional[GPSFix]:
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
            import threading
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
        import serial
        import pynmea2
        
        try:
            with serial.Serial(self.device, 9600, timeout=1) as ser:
                while self._running:
                    line = ser.readline().decode('ascii', errors='replace').strip()
                    if line.startswith('$GPGGA') or line.startswith('$GNGGA'):
                        try:
                            msg = pynmea2.parse(line)
                            if msg.lat and msg.lon:
                                self._last_fix = GPSFix(
                                    lat=msg.latitude,
                                    lon=msg.longitude,
                                    alt=msg.altitude,
                                    speed=0.0, # NMEA GGA doesn't have speed, need RMC
                                    accuracy_m=float(msg.horizontal_dil) if msg.horizontal_dil else 5.0,
                                    timestamp=datetime.now(timezone.utc).isoformat()
                                )
                        except pynmea2.ParseError:
                            continue
        except Exception as e:
            logger.error(f"GPS Error: {e}")


class WardriveSession:
    """Manage wardriving session"""

    def __init__(self, sensor_id: str, output_path: Path):
        self.sensor_id = sensor_id
        self.output_path = output_path
        self.sightings: List[WardriveSighting] = []
        self.unique_bssids: set = set()
        self.start_time = datetime.now(timezone.utc)
        self._running = False

    def add_sighting(self, sighting: WardriveSighting):
        """Add a network sighting"""
        self.sightings.append(sighting)
        is_new = sighting.bssid not in self.unique_bssids
        self.unique_bssids.add(sighting.bssid)
        return is_new

    def save(self):
        """Save session to file"""
        data = {
            'session_id': f"wardrive_{self.start_time.strftime('%Y%m%d_%H%M%S')}",
            'sensor_id': self.sensor_id,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now(
                timezone.utc).isoformat(),
            'total_sightings': len(
                self.sightings),
            'unique_networks': len(
                self.unique_bssids),
            'sightings': [
                asdict(s) for s in self.sightings]}

        with open(self.output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(
            f"Saved {len(self.sightings)} sightings to {self.output_path}")

    def print_stats(self):
        """Print session statistics"""
        duration = (
            datetime.now(
                timezone.utc)
            - self.start_time).total_seconds()
        print(f"\n{'='*50}")
        print("Wardrive Session Statistics")
        print(f"{'='*50}")
        print(f"Duration:        {duration:.1f} seconds")
        print(f"Total Sightings: {len(self.sightings)}")
        print(f"Unique Networks: {len(self.unique_bssids)}")
        print(
            f"Rate:            {len(self.sightings)/max(duration,1):.1f} sightings/sec")
        print(f"{'='*50}\n")


class WardriveCapture:
    """Capture networks during wardriving"""

    def __init__(self, iface: str, mock: bool = False, timeout: float = 1.0):
        self.iface = iface
        self.mock = mock
        self.timeout = timeout
        self._running = False

    def start(self):
        """Start capture"""
        self._running = True
        if self.mock:
            logger.info(f"Capture: Mock mode on {self.iface}")
        else:
            logger.info(f"Capture: Starting on {self.iface}")

    def stop(self):
        """Stop capture"""
        self._running = False

    def get_networks(self) -> List[Dict]:
        """Get currently visible networks"""
        if self.mock:
            return self._mock_networks()

        # Real Capture using Scapy
        try:
            from scapy.all import sniff, Dot11Beacon, Dot11, RadioTap
            
            # Sniff for a short duration
            packets = sniff(iface=self.iface, timeout=self.timeout, count=50, verbose=False)
            
            networks = []
            seen_bssids = set()
            
            for pkt in packets:
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    if bssid in seen_bssids:
                        continue
                    seen_bssids.add(bssid)
                    
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt.haslayer(Dot11Elt) else "<Hidden>"
                    
                    # Extract RSSI (Signal Strength)
                    rssi = -100
                    if pkt.haslayer(RadioTap):
                        try:
                            rssi = pkt[RadioTap].dBm_AntSignal
                        except:
                            pass
                            
                    # Extract Channel
                    channel = 0
                    try:
                        channel = int(ord(pkt[Dot11Elt:3].info))
                    except:
                        pass
                        
                    # Determine Security
                    security = "Open"
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                    if "privacy" in cap:
                        security = "WPA2" # Simplified assumption for wardriving
                        
                    networks.append({
                        'bssid': bssid,
                        'ssid': ssid,
                        'rssi_dbm': rssi,
                        'channel': channel,
                        'security': security
                    })
                    
            return networks
            
        except ImportError:
            if not self.mock:
                logger.critical("Scapy not installed but required for real capture. Run: pip install scapy")
                sys.exit(1)
            return []
        except Exception as e:
            logger.error(f"Capture error: {e}")
            return []

    def _mock_networks(self) -> List[Dict]:
        """Generate mock network data"""
        import random

        networks = []
        for i in range(random.randint(1, 5)):
            networks.append({
                'bssid': f"AA:BB:CC:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}",
                'ssid': random.choice(['CafeWiFi', 'HomeNet', 'Office_5G', None, 'FreeWiFi']),
                'rssi_dbm': random.randint(-90, -30),
                'channel': random.choice([1, 6, 11, 36, 44]),
                'security': random.choice(['WPA2', 'WPA3', 'WEP', 'Open'])
            })
        return networks


def run_wardrive(args):
    """Main wardrive loop"""

    # Initialize components
    gps = GPSReader(device=args.gps, mock=args.mock_gps)
    capture = WardriveCapture(iface=args.iface, mock=args.mock_capture)
    session = WardriveSession(
        sensor_id=args.sensor_id,
        output_path=Path(args.output)
    )

    # Signal handler for graceful shutdown
    def shutdown(sig, frame):
        logger.info("Shutting down...")
        capture.stop()
        gps.stop()
        session.save()
        session.print_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start components
    gps.start()
    capture.start()

    logger.info("Wardriving started. Press Ctrl+C to stop.")
    logger.info(f"Output: {args.output}")

    # Main loop
    scan_count = 0
    while True:
        try:
            # Get GPS fix
            gps_fix = gps.get_fix()

            # Get visible networks
            networks = capture.get_networks()

            # Record sightings
            for net in networks:
                sighting = WardriveSighting(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    bssid=net['bssid'],
                    ssid=net.get('ssid'),
                    rssi_dbm=net['rssi_dbm'],
                    channel=net['channel'],
                    security=net['security'],
                    gps=gps_fix,
                    sensor_id=args.sensor_id
                )
                is_new = session.add_sighting(sighting)

                if is_new and sighting.ssid:
                    logger.info(
                        f"NEW: {sighting.ssid} ({sighting.bssid}) "
                        f"[{sighting.security}] {sighting.rssi_dbm}dBm")

            scan_count += 1
            if scan_count % 10 == 0:
                logger.info(
                    f"Scans: {scan_count}, Networks: {len(session.unique_bssids)}")

            # Wait before next scan
            time.sleep(args.interval)

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(
        description='Sentinel NetLab Wardriving Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mock mode (no hardware)
  python wardrive.py --sensor-id test-01 --mock-capture --mock-gps

  # Real capture with GPS
  python wardrive.py --sensor-id pi-01 --iface wlan0mon --gps /dev/ttyUSB0

  # Custom output location
  python wardrive.py --sensor-id pi-01 --iface wlan0mon --output /data/session.json

IMPORTANT: Use only on networks you own or have authorization to monitor.
See ETHICS.md for legal guidelines.
        """
    )

    parser.add_argument(
        '--sensor-id',
        required=True,
        help='Unique sensor identifier')
    parser.add_argument(
        '--iface',
        default='wlan0',
        help='WiFi interface (default: wlan0)')
    parser.add_argument('--gps', help='GPS device path (e.g., /dev/ttyUSB0)')
    parser.add_argument(
        '--output',
        default='wardrive_session.json',
        help='Output file path')
    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='Scan interval in seconds')
    parser.add_argument(
        '--mock-capture',
        action='store_true',
        help='Use mock capture (no hardware)')
    parser.add_argument(
        '--mock-gps',
        action='store_true',
        help='Use mock GPS data')

    args = parser.parse_args()

    # Print warning
    print("\n" + "=" * 60)
    print("⚠️  SENTINEL NETLAB WARDRIVING TOOL")
    print("=" * 60)
    print("This tool captures WiFi network information.")
    print("Use ONLY on networks you own or have authorization to monitor.")
    print("See ETHICS.md for legal guidelines.")
    print("=" * 60 + "\n")

    run_wardrive(args)


if __name__ == '__main__':
    main()
