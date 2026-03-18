#!/usr/bin/env python3
"""
Sentinel NetLab - Live Evil Twin Detector
Uses Scapy to sniff real-time 802.11 Beacon frames and feed them into the detection algorithm.
Requires a wireless interface in monitor mode.
"""

import argparse
import sys
from pathlib import Path

# Add the project root to the python path so we can import algos
sys.path.append(str(Path(__file__).resolve().parent.parent))

from scapy.all import Dot11Beacon, sniff

from algos.evil_twin import AdvancedEvilTwinDetector, EvilTwinConfig


def get_cli_config():
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab - Live Evil Twin Detector"
    )
    parser.add_argument(
        "--iface",
        type=str,
        required=True,
        help="Network interface in monitor mode (e.g., wlan0mon)",
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

    return parser.parse_args()


def main():
    args = get_cli_config()

    config = EvilTwinConfig(
        rssi_delta_threshold=args.rssi_delta,
        confirmation_window_seconds=args.confirm_window,
        threshold_critical=args.critical_score,
    )

    detector = AdvancedEvilTwinDetector(config)
    print("\n" + "=" * 60)
    print("LIVE ADVANCED EVIL TWIN DETECTOR")
    print("=" * 60)
    print(f"[i] Interface: {args.iface}")
    print(f"[i] Confirmation Window: {config.confirmation_window_seconds}s")
    print(f"[i] RSSI Delta Threshold: {config.rssi_delta_threshold} dB")
    print(f"[i] Critical Score Threshold: {config.threshold_critical}")
    print(
        "\n[+] Listening for real-time 802.11 Beacon frames... (Press Ctrl+C to stop)"
    )

    def packet_handler(pkt):
        # We only care about Beacon frames for Evil Twin detection
        if pkt.haslayer(Dot11Beacon):
            try:
                # Basic fields
                bssid = pkt.addr2
                # Note: Scapy's info field contains the SSID
                ssid = pkt.info.decode(errors="ignore") if pkt.info else ""

                # Default RSSI if unavailable
                rssi = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -50

                # In real scenario we'd parse this properly, using default or simple extraction
                channel = 0
                try:
                    # Dot11Elt with ID 3 is usually the DS Parameter Set (channel)
                    # For a robust solution, we'd iterate over Dot11Elt layers
                    layer = pkt.getlayer(Dot11Beacon).payload
                    while layer:
                        if layer.ID == 3:
                            channel = int(layer.info[0])
                            break
                        layer = layer.payload
                except Exception:
                    channel = 0  # Fallback

                # Derive vendor OUI from first 3 octets (8 characters: "XX:YY:ZZ")
                vendor_oui = bssid[:8].upper() if bssid else ""

                telemetry = {
                    "bssid": bssid,
                    "ssid": ssid,
                    "rssi_dbm": rssi,
                    "channel": channel,
                    "vendor_oui": vendor_oui,
                    "sensor_id": "live-sensor",
                }

                # Feed the telemetry into the detector
                alerts = detector.ingest(telemetry)
                if alerts:
                    for alert in alerts:
                        print("\n[!] PHÁT HIỆN THỰC TẾ (LIVE ALERT):")
                        print(f"    Mức độ (Severity): {alert.severity}")
                        print(f"    SSID: {alert.ssid}")
                        print(f"    AP Gốc (Original): {alert.original_bssid}")
                        print(f"    AP Giả mạo (Suspect): {alert.suspect_bssid}")
                        print(f"    Lý do: {', '.join(alert.reason_codes)}")

            except AttributeError:
                pass
            except Exception as e:
                # Catch general exceptions to prevent the sniffer from crashing
                print(f"[!] Error processing packet: {e}")

    # Sniff on the provided interface
    try:
        sniff(iface=args.iface, prn=packet_handler, store=0)
    except Exception as e:
        print(f"\n[!] Failed to start sniffing on {args.iface}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
