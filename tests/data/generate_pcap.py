#!/usr/bin/env python3
# ruff: noqa: F403, F405
"""
Generate Golden PCAP Dataset for Sentinel NetLab
Creates a synthetic 802.11 pcap with:
1. Normal Traffic (Beacon, Probe, Assoc)
2. Evil Twin Attack (Cloned SSID, Signal Anomaly)
3. Deauth Flood (High rate management frames)
"""

import os

from scapy.all import *

# Ensure output directory exists
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "golden_vectors.pcap")


def create_beacon(ssid, bssid, channel=6, rssi=-60, seq=0):
    """Create an 802.11 Beacon Frame"""
    dot11 = Dot11(
        type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=seq << 4
    )
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    dsset = Dot11Elt(ID="DSset", info=chr(channel))

    # RadioTap for RSSI
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=rssi)

    return radiotap / dot11 / beacon / essid / dsset


def create_deauth(target, bssid, reason=7, seq=0):
    """Create a Deauthentication Frame"""
    dot11 = Dot11(type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid, SC=seq << 4)
    deauth = Dot11Deauth(reason=reason)
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=-55)
    return radiotap / dot11 / deauth


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["all", "normal", "evil_twin", "deauth"], default="all")
    parser.add_argument("--output", default=OUTPUT_FILE)
    args = parser.parse_args()

    print(f"Generating {args.scenario} scenario(s) at: {args.output}")
    packets = []

    legit_bssid = "DC:A6:32:33:44:55"
    client_mac = "aa:bb:cc:dd:ee:ff"
    
    if args.scenario in ["all", "normal"]:
        print("[-] Generating Normal Traffic...")
        for i in range(10):
            packets.append(create_beacon("Corporate_WiFi", legit_bssid, channel=6, rssi=-60, seq=i))
        
        packets.append(
            RadioTap()
            / Dot11(
                type=0,
                subtype=4,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=client_mac,
                addr3="ff:ff:ff:ff:ff:ff",
                SC=10 << 4
            )
            / Dot11ProbeReq()
            / Dot11Elt(ID="SSID", info="Corporate_WiFi")
        )

    if args.scenario in ["all", "evil_twin"]:
        print("[-] Generating Evil Twin Attack (prepending legit beacons)...")
        # Legit AP baseline
        for i in range(5):
            packets.append(create_beacon("Corporate_WiFi", legit_bssid, channel=6, rssi=-60, seq=i))
            
        # Evil Twin
        evil_bssid = "de:ad:be:ef:00:00"
        print("[-] Generating Evil Twin frames...")
        for i in range(20):
            packets.append(create_beacon("Corporate_WiFi", evil_bssid, channel=6, rssi=-30, seq=i))

    if args.scenario in ["all", "deauth"]:
        print("[-] Generating Deauth Flood...")
        for i in range(100):
            packets.append(create_deauth(client_mac, legit_bssid, seq=i))

    # Save
    wrpcap(args.output, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
