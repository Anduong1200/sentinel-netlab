#!/usr/bin/env python3
"""
Sentinel NetLab - Unified CLI
Wrapper for Wardriving (Assessment) and Sensor (WIDS) modes.
"""

import argparse
import os
import sys

# Load .env explicitly for CLI usage
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add project root to path (Two levels up from scripts/entrypoint.py)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_wardrive_parser(subparsers):
    parser = subparsers.add_parser("scan", help="Wardriving / Assessment Mode")
    parser.add_argument("--sensor-id", default="sentinel-mobile", help="Sensor ID")
    parser.add_argument("--iface", default="wlan0", help="Interface")
    parser.add_argument("--gps", help="GPS Device (e.g., /dev/ttyUSB0)")
    parser.add_argument("--output", default="session.json", help="Output file")
    parser.add_argument("--interval", type=float, default=1.0, help="Scan interval")
    parser.add_argument("--mock-capture", action="store_true", help="Mock capture")
    parser.add_argument("--mock-gps", action="store_true", help="Mock GPS")
    parser.set_defaults(func=run_wardrive_wrapper)


def run_wardrive_wrapper(args):
    from sensor.wardrive import run_wardrive

    print("=" * 50)
    print("Sentinel NetLab: ASSESSMENT MODE (Wardriving)")
    print("=" * 50)
    try:
        run_wardrive(args)
    except KeyboardInterrupt:
        pass


def setup_monitor_parser(subparsers):
    parser = subparsers.add_parser("monitor", help="WIDS / Continuous Monitoring Mode")
    parser.add_argument("-i", "--interface", default="wlan0", help="Interface")
    parser.add_argument("-c", "--channels", default="1,6,11", help="Channels")
    parser.add_argument(
        "--engine", choices=["scapy", "tshark"], default="scapy", help="Engine"
    )
    parser.add_argument("--no-hop", action="store_true", help="Disable hopping")
    parser.add_argument("--api", action="store_true", help="Enable API")
    parser.add_argument("--host", default="0.0.0.0", help="API Host")
    parser.add_argument("--port", type=int, default=5000, help="API Port")
    parser.add_argument(
        "--buffered-storage", action="store_true", help="Buffered Storage"
    )
    parser.add_argument("--watchdog", action="store_true", help="USB Watchdog")
    parser.add_argument("--db", default="wifi_scanner.db", help="DB Path")
    parser.set_defaults(func=run_monitor_wrapper)


def run_monitor_wrapper(args):
    from sensor.cli import (
        merge_config,
        print_banner,
        run_sensor_logic,
        setup_logging,
    )

    print("=" * 50)
    print("Sentinel NetLab: MONITOR MODE (WIDS) [Modern Architecture]")
    print("=" * 50)

    # Normalize arguments for sensor.cli compatibility
    if not hasattr(args, "iface"):
        args.iface = args.interface
    
    # Set defaults for missing args (since we use a subset in this wrapper)
    defaults = {
        "sensor_id": os.environ.get("SENSOR_ID", "sentinel-monitor-cli"),
        "mock_mode": False,
        "dwell_ms": 200,
        "upload_url": args.host if hasattr(args, "host") and "http" in args.host else f"http://{args.host}:{args.port}/api/v1/telemetry",
        "auth_token": os.environ.get("SENTINEL_AUTH_KEY", "dev-key"),
        "batch_size": 200,
        "upload_interval": 5.0,
        "storage_path": os.path.join(os.getcwd(), "journal"),
        "anonymize_ssid": False,
        "store_raw_mac": False,
        "privacy_mode": "anonymized",
        "log_level": "INFO",
        "gps_device": None
    }
    
    for k, v in defaults.items():
        if not hasattr(args, k):
            setattr(args, k, v)

    # Merge with empty file config (defaults)
    config = merge_config(args, {})
    
    # Initialize system
    setup_logging(config["logging"]["level"])
    print_banner(config)
    
    # Run
    run_sensor_logic(config)


def main():
    parser = argparse.ArgumentParser(description="Sentinel NetLab Unified CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_wardrive_parser(subparsers)
    setup_monitor_parser(subparsers)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
