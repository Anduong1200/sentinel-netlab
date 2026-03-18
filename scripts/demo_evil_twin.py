#!/usr/bin/env python3
"""
Sentinel NetLab - Advanced Evil Twin Detector Demo
Simulates an Evil Twin attack using mock data to demonstrate the detection algorithm.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Add the project root to the python path so we can import algos
sys.path.append(str(Path(__file__).resolve().parent.parent))

from algos.evil_twin import AdvancedEvilTwinDetector, EvilTwinConfig


def get_cli_config() -> EvilTwinConfig:
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab - Evil Twin Detector Demo"
    )
    parser.add_argument(
        "--rssi-delta",
        type=int,
        default=15,
        help="Ngưỡng chênh lệch tín hiệu (dB) / RSSI Delta Threshold",
    )
    parser.add_argument(
        "--confirm-window",
        type=int,
        default=30,
        help="Thời gian chờ xác nhận cảnh báo (giây) / Confirmation window (seconds)",
    )
    parser.add_argument(
        "--critical-score",
        type=int,
        default=80,
        help="Điểm số để kích hoạt mức CRITICAL / Critical score threshold",
    )

    args = parser.parse_args()

    # Load into configuration
    return EvilTwinConfig(
        rssi_delta_threshold=args.rssi_delta,
        confirmation_window_seconds=args.confirm_window,
        threshold_critical=args.critical_score,
    )


def main():
    """Demo the advanced detector"""
    print("\n" + "=" * 60)
    print("ADVANCED EVIL TWIN DETECTOR DEMO")
    print("=" * 60)

    config = get_cli_config()
    detector = AdvancedEvilTwinDetector(config)
    print(
        f"[i] Initialized Detector with Confirmation Window = {config.confirmation_window_seconds}s"
    )

    # Simulate legitimate AP (build history)
    print("\n[+] Building baseline for 'CorporateWiFi'...")
    for i in range(50):
        detector.ingest(
            {
                "bssid": "AA:BB:CC:11:22:33",
                "ssid": "CorporateWiFi",
                "channel": 6,
                "rssi_dbm": -65 + (i % 5 - 2),  # Normal variation
                "vendor_oui": "AA:BB:CC",
                "capabilities": {"privacy": True, "pmf": True},
                "rsn_info": {"akm": ["PSK"]},
                "beacon_interval": 100,
                "sensor_id": "demo-sensor",
            }
        )

    print(f"    Tracked APs: {detector.get_stats()['tracked_aps']}")

    # Inject evil twin
    print("\n[!] Injecting Evil Twin AP...")
    alerts = detector.ingest(
        {
            "bssid": "DE:AD:BE:EF:00:01",
            "ssid": "CorporateWiFi",  # Same SSID
            "channel": 6,
            "rssi_dbm": -35,  # Much stronger (attacker closer)
            "vendor_oui": "DE:AD:BE",  # Different vendor!
            "capabilities": {"privacy": True, "pmf": False},  # Different PMF
            "rsn_info": {"akm": ["PSK"]},
            "beacon_interval": 102,
            "sensor_id": "demo-sensor",
            "ies_present": ["SSID", "RSN"],  # Missing some IEs
        }
    )

    # Since confirmation window, simulate second observation
    time.sleep(0.1)
    for _ in range(3):
        alerts = detector.ingest(
            {
                "bssid": "DE:AD:BE:EF:00:01",
                "ssid": "CorporateWiFi",
                "channel": 6,
                "rssi_dbm": -33,
                "vendor_oui": "DE:AD:BE",
                "capabilities": {"privacy": True, "pmf": False},
                "rsn_info": {"akm": ["PSK"]},
                "beacon_interval": 105,
                "sensor_id": "demo-sensor",
            }
        )

    # Force confirmation with high score
    # In real scenario, this happens after confirmation_window_seconds
    # NOTE: The user requested to use CLI config, so if `--confirm-window 0` is passed,
    # the window is automatically bypassed. In the previous code this was hardcoded to 0 at the end.

    alerts = detector.ingest(
        {
            "bssid": "DE:AD:BE:EF:00:01",
            "ssid": "CorporateWiFi",
            "channel": 6,
            "rssi_dbm": -30,
            "vendor_oui": "DE:AD:BE",
            "capabilities": {"privacy": True, "pmf": False},
            "sensor_id": "demo-sensor",
        }
    )

    if alerts:
        for alert in alerts:
            print(f"\n⚠️  ALERT: {alert.severity}")
            print(f"    ID: {alert.alert_id}")
            print(f"    Score: {alert.score}/100")
            print(f"    SSID: {alert.ssid}")
            print(f"    Original: {alert.original_bssid}")
            print(f"    Suspect: {alert.suspect_bssid}")
            print(f"    MITRE: {alert.mitre_technique}")
            print(f"    Recommendation: {alert.recommendation[:80]}...")
    else:
        print("    (Alert pending confirmation...)")

    print(f"\n[+] Stats: {json.dumps(detector.get_stats(), indent=2)}")


if __name__ == "__main__":
    main()
