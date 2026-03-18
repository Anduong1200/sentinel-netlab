#!/usr/bin/env python3
# ruff: noqa: F403, F405
"""
Generate Golden PCAP Dataset for Sentinel NetLab
Creates a synthetic 802.11 pcap with:
1. Normal Traffic (Beacon, Probe, Assoc)
2. Evil Twin Attack (Cloned SSID, Signal Anomaly)
3. Deauth Flood (High rate management frames)
4. Disassociation Flood (High rate disassociation frames)
5. Beacon Flood (Massive random fake APs)
6. Karma Attack (Responding to multiple different Probe Requests)
7. PMKID Harvesting (Rapid Auth/Assoc to capture EAPOL M1)
"""

import os

from scapy.all import *

# Ensure output directory exists
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "golden_vectors.pcap")


def create_beacon(ssid, bssid, channel=6, rssi=-60, seq=0):
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
        SC=seq << 4,
    )
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    dsset = Dot11Elt(ID="DSset", info=chr(channel))
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=rssi)
    return radiotap / dot11 / beacon / essid / dsset


def create_deauth(target, bssid, reason=7, seq=0):
    dot11 = Dot11(
        type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid, SC=seq << 4
    )
    deauth = Dot11Deauth(reason=reason)
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=-55)
    return radiotap / dot11 / deauth


def create_disassoc(target, bssid, reason=8, seq=0):
    dot11 = Dot11(
        type=0, subtype=10, addr1=target, addr2=bssid, addr3=bssid, SC=seq << 4
    )
    disassoc = Dot11Disas(reason=reason)
    radiotap = RadioTap(present=0xDB00, dBm_AntSignal=-55)
    return radiotap / dot11 / disassoc


def create_probe_resp(ssid, bssid, client, channel=6, rssi=-40, seq=0):
    dot11 = Dot11(
        type=0, subtype=5, addr1=client, addr2=bssid, addr3=bssid, SC=seq << 4
    )
    probe_resp = Dot11ProbeResp(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    dsset = Dot11Elt(ID="DSset", info=chr(channel))
    return (
        RadioTap(present=0xDB00, dBm_AntSignal=rssi)
        / dot11
        / probe_resp
        / essid
        / dsset
    )


def create_auth(client, bssid, seq=0):
    dot11 = Dot11(
        type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid, SC=seq << 4
    )
    auth = Dot11Auth(algo=0, seqnum=1, status=0)
    return RadioTap(present=0xDB00, dBm_AntSignal=-50) / dot11 / auth


def create_assoc_req(client, bssid, ssid, seq=0):
    dot11 = Dot11(
        type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid, SC=seq << 4
    )
    assoc = Dot11AssoReq()
    essid = Dot11Elt(ID="SSID", info=ssid)
    return RadioTap(present=0xDB00, dBm_AntSignal=-50) / dot11 / assoc / essid


def create_eapol_m1(bssid, client, seq=0):
    dot11 = Dot11(
        type=2, subtype=8, addr1=client, addr2=bssid, addr3=bssid, SC=seq << 4
    )
    llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    snap = SNAP(OUI=0x000000, code=0x888E)
    eapol = EAPOL(version=1, type=3, len=95)
    return RadioTap(present=0xDB00, dBm_AntSignal=-60) / dot11 / llc / snap / eapol


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenario",
        choices=[
            "all",
            "normal",
            "evil_twin",
            "deauth",
            "disassoc_flood",
            "beacon_flood",
            "karma",
            "pmkid",
        ],
        default="all",
    )
    parser.add_argument("--output", default=OUTPUT_FILE)
    args = parser.parse_args()

    print(f"Generating {args.scenario} scenario(s) at: {args.output}")
    packets = []

    legit_bssid = "DC:A6:32:33:44:55"
    client_mac = "aa:bb:cc:dd:ee:ff"

    if args.scenario in ["all", "normal"]:
        print("[-] Generating Normal Traffic...")
        for i in range(10):
            packets.append(
                create_beacon("Corporate_WiFi", legit_bssid, channel=6, rssi=-60, seq=i)
            )
        packets.append(
            RadioTap()
            / Dot11(
                type=0,
                subtype=4,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=client_mac,
                addr3="ff:ff:ff:ff:ff:ff",
                SC=10 << 4,
            )
            / Dot11ProbeReq()
            / Dot11Elt(ID="SSID", info="Corporate_WiFi")
        )

    if args.scenario in ["all", "evil_twin"]:
        print("[-] Generating Evil Twin Attack (prepending legit beacons)...")
        for i in range(5):
            packets.append(
                create_beacon("Corporate_WiFi", legit_bssid, channel=6, rssi=-60, seq=i)
            )
        evil_bssid = "de:ad:be:ef:00:00"
        print("[-] Generating Evil Twin frames...")
        for i in range(20):
            packets.append(
                create_beacon("Corporate_WiFi", evil_bssid, channel=6, rssi=-30, seq=i)
            )

    if args.scenario in ["all", "deauth"]:
        print("[-] Generating Deauth Flood...")
        for i in range(100):
            packets.append(create_deauth(client_mac, legit_bssid, seq=i))

    if args.scenario in ["all", "disassoc_flood"]:
        print("[-] Generating Disassociation Flood...")
        for i in range(100):
            packets.append(create_disassoc(client_mac, legit_bssid, reason=8, seq=i))

    if args.scenario in ["all", "beacon_flood"]:
        print("[-] Generating Beacon Flood (Fake APs)...")
        import secrets

        for i in range(200):
            rand_bssid = RandMAC()
            fake_ssid = f"Free_WiFi_{i}"
            # Select random channel from 1 to 11
            channel = 1 + secrets.randbelow(11)
            packets.append(
                create_beacon(fake_ssid, rand_bssid, channel=channel, rssi=-50, seq=i)
            )

    if args.scenario in ["all", "karma"]:
        print("[-] Generating Karma Attack...")
        attacker_bssid = "00:11:22:33:44:55"
        victim_probes = [
            ("11:22:33:44:55:66", "Home_Network"),
            ("aa:bb:cc:11:22:33", "Cafe_Free_WiFi"),
            ("dd:ee:ff:11:22:33", "Hotel_Guest"),
        ]
        seq = 0
        for client, ssid in victim_probes:
            # Victim sends probe request for a specific network
            packets.append(
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=4,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=client,
                    addr3="ff:ff:ff:ff:ff:ff",
                    SC=seq << 4,
                )
                / Dot11ProbeReq()
                / Dot11Elt(ID="SSID", info=ssid)
            )
            seq += 1
            # Attacker instantly responds claiming to be that exact network
            packets.append(create_probe_resp(ssid, attacker_bssid, client, seq=seq))
            seq += 1

    if args.scenario in ["all", "pmkid"]:
        print("[-] Generating PMKID Harvesting Attack...")
        attacker_mac = "66:66:66:66:66:66"
        for i in range(5):
            # 1. Attacker authenticates
            packets.append(create_auth(attacker_mac, legit_bssid, seq=i * 3))
            # 2. Attacker associates
            packets.append(
                create_assoc_req(
                    attacker_mac, legit_bssid, "Corporate_WiFi", seq=i * 3 + 1
                )
            )
            # 3. AP responds with EAPOL M1 (contains the PMKID)
            packets.append(create_eapol_m1(legit_bssid, attacker_mac, seq=i * 3 + 2))

    # Save
    wrpcap(args.output, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
