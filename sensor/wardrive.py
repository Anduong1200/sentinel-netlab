#!/usr/bin/env python3
"""
Sentinel NetLab - Wardriving CLI
Capture WiFi networks while mobile with GPS correlation.

Usage:
    python wardrive.py --iface wlan0 --gps /dev/ttyUSB0 --output session.json
"""

import argparse
import logging
import signal
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.gps.gps_reader import GPSReader

# GPSReader and GPSFix imported from common.gps.gps_reader


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

    def get_networks(self) -> list[dict]:
        """Get currently visible networks"""
        if self.mock:
            return self._mock_networks()

        # Real Capture using Scapy
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff

            # Sniff for a short duration
            packets = sniff(
                iface=self.iface, timeout=self.timeout, count=50, verbose=False
            )

            networks = []
            seen_bssids = set()

            for pkt in packets:
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    if bssid in seen_bssids:
                        continue
                    seen_bssids.add(bssid)

                    ssid = (
                        pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
                        if pkt.haslayer(Dot11Elt)
                        else "<Hidden>"
                    )

                    # Extract RSSI (Signal Strength)
                    rssi = -100
                    if pkt.haslayer(RadioTap):
                        try:
                            rssi = pkt[RadioTap].dBm_AntSignal
                        except:  # nosec B110
                            pass

                    # Extract Channel
                    channel = 0
                    try:
                        channel = int(ord(pkt[Dot11Elt:3].info))
                    except:  # nosec B110
                        pass

                    # Determine Security
                    security = "Open"
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                    if "privacy" in cap:
                        security = "WPA2"  # Simplified assumption for wardriving

                    networks.append(
                        {
                            "bssid": bssid,
                            "ssid": ssid,
                            "rssi_dbm": rssi,
                            "channel": channel,
                            "security": security,
                        }
                    )

            return networks

        except ImportError:
            if not self.mock:
                logger.critical(
                    "Scapy not installed but required for real capture. Run: pip install scapy"
                )
                sys.exit(1)
            return []
        except Exception as e:
            logger.error(f"Capture error: {e}")
            return []

    def _mock_networks(self) -> list[dict]:
        """Generate mock network data"""
        import random

        networks = []
        for _i in range(random.randint(1, 5)):  # nosec B311
            networks.append(
                {
                    "bssid": f"AA:BB:CC:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}",  # nosec B311
                    "ssid": random.choice(  # nosec B311
                        ["CafeWiFi", "HomeNet", "Office_5G", None, "FreeWiFi"]
                    ),
                    "rssi_dbm": random.randint(-90, -30),  # nosec B311
                    "channel": random.choice([1, 6, 11, 36, 44]),  # nosec B311
                    "security": random.choice(["WPA2", "WPA3", "WEP", "Open"]),  # nosec B311
                }
            )
        return networks


def run_wardrive(args):
    """Main wardrive loop"""

    # Initialize components
    gps = GPSReader(device=args.gps, mock=args.mock_gps)
    capture = WardriveCapture(iface=args.iface, mock=args.mock_capture)
    session = WardriveSession(sensor_id=args.sensor_id, output_path=Path(args.output))

    # Signal handler for graceful shutdown
    def shutdown(sig, frame):
        logger.info("Shutting down...")
        capture.stop()
        gps.stop()
        session.save()
        session.print_stats()

        # Upload if requested
        if args.upload and args.api_url:
            logger.info("Uploading session to controller...")
            session.upload_to_controller(args.api_url, args.api_key)

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
                    timestamp=datetime.now(UTC).isoformat(),
                    bssid=net["bssid"],
                    ssid=net.get("ssid"),
                    rssi_dbm=net["rssi_dbm"],
                    channel=net["channel"],
                    security=net["security"],
                    gps=gps_fix,
                    sensor_id=args.sensor_id,
                )
                is_new = session.add_sighting(sighting)

                if is_new and sighting.ssid:
                    logger.info(
                        f"NEW: {sighting.ssid} ({sighting.bssid}) "
                        f"[{sighting.security}] {sighting.rssi_dbm}dBm"
                    )

            scan_count += 1
            if scan_count % 10 == 0:
                logger.info(
                    f"Scans: {scan_count}, Networks: {len(session.unique_bssids)}"
                )

            # Wait before next scan
            time.sleep(args.interval)

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab Wardriving Tool",
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
        """,
    )

    parser.add_argument("--sensor-id", required=True, help="Unique sensor identifier")
    parser.add_argument(
        "--iface", default="wlan0", help="WiFi interface (default: wlan0)"
    )
    parser.add_argument("--gps", help="GPS device path (e.g., /dev/ttyUSB0)")
    parser.add_argument(
        "--output", default="wardrive_session.json", help="Output file path"
    )
    parser.add_argument(
        "--interval", type=float, default=1.0, help="Scan interval in seconds"
    )
    parser.add_argument(
        "--mock-capture", action="store_true", help="Use mock capture (no hardware)"
    )
    parser.add_argument("--mock-gps", action="store_true", help="Use mock GPS data")

    # Upload options
    parser.add_argument("--upload", action="store_true", help="Upload session at end")
    parser.add_argument(
        "--api-url", default="http://localhost:5000/api/v1", help="Controller API URL"
    )
    parser.add_argument(
        "--api-key", default="sentinel-dev-2024", help="API Key for upload"
    )

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


if __name__ == "__main__":
    main()
