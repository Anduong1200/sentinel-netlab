#!/usr/bin/env python3
"""
Sentinel NetLab Sensor - CLI Entry Point
Validates flags, loads config, and starts sensor controller.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

# Setup path
# Add sensor and project root to path
SENSOR_DIR = Path(__file__).parent
sys.path.insert(0, str(SENSOR_DIR))
sys.path.insert(0, str(SENSOR_DIR.parent))


def load_config(config_file: str | None = None) -> dict[str, Any]:
    """Load configuration from YAML file"""
    if config_file and Path(config_file).exists():
        with open(config_file) as f:
            return yaml.safe_load(f)

    # Try default locations
    default_paths = [
        SENSOR_DIR / "config.yaml",
        Path("/etc/sentinel/config.yaml"),
        Path.home() / ".sentinel/config.yaml",
    ]

    for path in default_paths:
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)

    return {}


def validate_preconditions(args: argparse.Namespace) -> bool:
    """Validate required preconditions before starting"""
    errors = []

    # Check sensor_id
    if not args.sensor_id:
        errors.append("--sensor-id is required")

    # Check interface (unless mock mode)
    if not args.mock_mode:
        if not args.iface:
            errors.append("--iface is required (or use --mock-mode)")
        elif not args.mock_mode:
            # Check if interface exists (Linux only)
            if sys.platform.startswith("linux"):
                if not Path(f"/sys/class/net/{args.iface}").exists():
                    errors.append(f"Interface {args.iface} not found")

    # Check upload URL format
    if args.upload_url:
        if not args.upload_url.startswith(("http://", "https://")):
            errors.append("--upload-url must start with http:// or https://")

    # Check channels format
    if args.channels:
        try:
            channels = [int(c.strip()) for c in args.channels.split(",")]
            for ch in channels:
                if not (1 <= ch <= 165):
                    errors.append(f"Invalid channel: {ch}")
        except ValueError:
            errors.append("--channels must be comma-separated integers")

    # Print errors and return
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return False

    return True


def merge_config(args: argparse.Namespace) -> Any:
    """Load config and apply CLI overrides"""
    import os

    from sensor.config import init_config

    config = (
        init_config(args.config_file)
        if getattr(args, "config_file", None)
        else init_config()
    )

    # Apply Overrides
    if getattr(args, "sensor_id", None):
        config.sensor.id = args.sensor_id
        os.environ["SENSOR_ID"] = args.sensor_id
    if getattr(args, "iface", None):
        config.capture.interface = args.iface
    if getattr(args, "channels", None):
        config.capture.channels = [int(c) for c in args.channels.split(",")]
    if getattr(args, "dwell_ms", None):
        config.capture.dwell_time = args.dwell_ms / 1000.0
    if getattr(args, "batch_size", None):
        config.upload.batch_size = args.batch_size
    if getattr(args, "upload_interval", None):
        config.upload.interval_sec = args.upload_interval
    if getattr(args, "upload_url", None):
        config.api.upload_url = args.upload_url
    if getattr(args, "auth_token", None):
        config.api.api_key = args.auth_token
    if getattr(args, "storage_path", None):
        config.storage.pcap_dir = args.storage_path

    # Privacy
    if getattr(args, "anonymize_ssid", False):
        config.privacy.anonymize_ssid = True
    if getattr(args, "store_raw_mac", False):
        config.privacy.store_raw_mac = True
    if getattr(args, "privacy_mode", None):
        config.privacy.mode = args.privacy_mode

    # Modes
    if getattr(args, "mock_mode", False):
        config.mock_mode = True
    if getattr(args, "pcap", None):
        config.capture.pcap_file = args.pcap
    if getattr(args, "enable_ml", False):
        config.ml.enabled = True
    if getattr(args, "enable_geo", False):
        config.geo.enabled = True

    # Logging
    if getattr(args, "log_level", None):
        config.log_level = args.log_level

    return config


def setup_logging(level: str) -> None:
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def print_banner(config: Any) -> None:
    """Print startup banner"""
    print("=" * 60)
    print("  Sentinel NetLab Sensor")
    print("  Lightweight Hybrid Wireless IDS")
    print("=" * 60)
    print(f"  Sensor ID:  {config.sensor.id}")
    print(f"  Interface:  {config.capture.interface}")
    print(f"  Channels:   {config.capture.channels}")
    print(f"  Mock Mode:  {config.mock_mode}")
    print(f"  Upload URL: {config.api.host}:{config.api.port}")
    if getattr(config.capture, "pcap_file", None):
        print(f"  PCAP File:  {config.capture.pcap_file}")
    if config.ml.enabled:
        print("  ML Boost:   ENABLED")
    if config.geo.enabled:
        print("  Geo Loc:    ENABLED")
    print("=" * 60)


def run_sensor_logic(config: dict) -> int:
    """Run the sensor logic with the given config"""
    # Import and start controller
    try:
        from sensor_controller import SensorController

        controller = SensorController(config=config)

        if controller.start():
            print("\nSensor running. Press Ctrl+C to stop.\n")

            import signal
            import time

            def shutdown(sig, frame):
                print("\nShutting down...")
                controller.stop()
                sys.exit(0)

            signal.signal(signal.SIGINT, shutdown)
            signal.signal(signal.SIGTERM, shutdown)

            while controller._running:
                time.sleep(1)
        else:
            print("ERROR: Failed to start sensor", file=sys.stderr)
            return 1

    except ImportError as e:
        print(f"ERROR: Failed to import sensor modules: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    """CLI main entry point"""
    parser = argparse.ArgumentParser(
        prog="sentinel-sensor",
        description="Sentinel NetLab Sensor - Wireless IDS Capture Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with real interface
  %(prog)s --sensor-id rpi-01 --iface wlan0mon

  # Mock mode for testing
  %(prog)s --sensor-id test-01 --iface mock0 --mock-mode

  # Custom channels and dwell time
  %(prog)s --sensor-id lab-01 --iface wlan0mon --channels 1,6,11 --dwell-ms 300

  # Use config file
  %(prog)s --config-file /etc/sentinel/config.yaml
        """,
    )

    # Required
    parser.add_argument("--sensor-id", help="Unique sensor identifier")
    parser.add_argument("--iface", help="Network interface")

    # Capture
    parser.add_argument("--channels", help="Comma-separated channel list")
    parser.add_argument("--dwell-ms", type=int, help="Channel dwell time (ms)")

    # Batching
    parser.add_argument("--batch-size", type=int, help="Max items per batch")
    parser.add_argument("--upload-interval", type=float, help="Upload interval (sec)")

    # Transport
    parser.add_argument("--upload-url", help="Controller telemetry endpoint")
    parser.add_argument("--auth-token", help="Authentication token")

    # Storage
    parser.add_argument("--storage-path", help="Journal storage path")
    parser.add_argument("--max-disk-usage", type=int, help="Max disk MB for journals")

    # Mode
    parser.add_argument(
        "--mock-mode", action="store_true", help="Use mock capture driver"
    )
    parser.add_argument("--pcap", help="Replay PCAP file instead of live capture")
    parser.add_argument(
        "--enable-ml", action="store_true", help="Enable ML Risk Scoring Boost"
    )
    parser.add_argument(
        "--enable-geo", action="store_true", help="Enable Geo-Location triangulation"
    )
    parser.add_argument(
        "--mode", choices=["capture", "test"], default="capture", help="Operation mode"
    )

    # Privacy
    parser.add_argument("--anonymize-ssid", action="store_true", help="Hash SSIDs")
    parser.add_argument(
        "--store-raw-mac",
        action="store_true",
        help="Store raw MAC addresses (warning: privacy risk)",
    )
    parser.add_argument(
        "--privacy-mode",
        choices=["normal", "anonymized", "private"],
        default="anonymized",
        help="Privacy mode for data retention",
    )

    # GPS
    parser.add_argument("--gps-device", help="GPS NMEA device path")

    # Sync
    parser.add_argument(
        "--ntp-sync", action="store_true", help="Ensure NTP sync on start"
    )

    # Logging
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level"
    )

    # Config
    parser.add_argument("--config-file", help="YAML config file path")

    # Lab safety
    parser.add_argument(
        "--confirm-lab-actions", action="store_true", help="Confirm lab/attack actions"
    )

    args = parser.parse_args()

    # Merge config
    config = merge_config(args)

    # Setup logging
    setup_logging(config.log_level)

    # Print banner
    print_banner(config)

    return run_sensor_logic(config)


if __name__ == "__main__":
    sys.exit(main())
