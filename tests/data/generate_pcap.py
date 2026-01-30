#!/usr/bin/env python3
"""
Generate Golden PCAP Dataset for Sentinel NetLab
Creates a synthetic 802.11 pcap with:
1. Normal Traffic (Beacon, Probe, Assoc)
2. Evil Twin Attack (Cloned SSID, Signal Anomaly)
3. Deauth Flood (High rate management frames)
"""

import os
import sys
from scapy.all import *

# Ensure output directory exists
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "golden_vectors.pcap")


def create_beacon(ssid, bssid, channel=6, rssi=-60):
    """Create an 802.11 Beacon Frame"""
    dot11 = Dot11(
        type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid
    )
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    dsset = Dot11Elt(ID="DSset", info=chr(channel))

    # RadioTap for RSSI
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=rssi)

    return radiotap / dot11 / beacon / essid / dsset


def create_deauth(target, bssid, reason=7):
    """Create a Deauthentication Frame"""
    dot11 = Dot11(type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid)
    deauth = Dot11Deauth(reason=reason)
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=-55)
    return radiotap / dot11 / deauth


def main():
    print(f"Generating Golden PCAP at: {OUTPUT_FILE}")
    packets = []

    # -------------------------------------------------------------------------
    # Scenario 1: Normal Network "Corporate_WiFi"
    # -------------------------------------------------------------------------
    legit_bssid = "00:11:22:33:44:55"
    client_mac = "aa:bb:cc:dd:ee:ff"

    print("[-] Generating Normal Traffic...")
    # 10 Beacons over 1 sec
    for i in range(10):
        packets.append(
            create_beacon("Corporate_WiFi", legit_bssid, channel=6, rssi=-60)
        )

    # Client Probes
    packets.append(
        RadioTap()
        / Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=client_mac,
            addr3="ff:ff:ff:ff:ff:ff",
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info="Corporate_WiFi")
    )

    # -------------------------------------------------------------------------
    # Scenario 2: Evil Twin Attack
    # Same SSID, Different BSSID, Stronger Signal (Suspicious)
    # -------------------------------------------------------------------------
    evil_bssid = "de:ad:be:ef:00:00"

    print("[-] Generating Evil Twin Attack...")
    for i in range(20):
        # RSSI -30 (Much stronger than legit -60, anomaly)
        packets.append(create_beacon("Corporate_WiFi", evil_bssid, channel=6, rssi=-30))

    # -------------------------------------------------------------------------
    # Scenario 3: Deauth Flood
    # -------------------------------------------------------------------------
    print("[-] Generating Deauth Flood...")
    # 100 Frames in quick succession
    for i in range(100):
        packets.append(create_deauth(client_mac, legit_bssid))

    # Save
    wrpcap(OUTPUT_FILE, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
