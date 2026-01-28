#!/usr/bin/env python3
"""
Forensics Module - Offline PCAP Analysis for Attack Detection
Analyzes captured PCAP files to detect Deauth floods, Evil Twins, etc.
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp, rdpcap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ForensicAnalyzer:
    """
    Analyzes PCAP files for attack signatures and anomalies.
    """

    def __init__(self, pcap_path: str):
        """
        Initialize analyzer with a PCAP file path.

        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = pcap_path
        self.packets = []
        self.loaded = False

    def load_pcap(self) -> bool:
        """Load PCAP file into memory."""
        try:
            self.packets = rdpcap(self.pcap_path)
            self.loaded = True
            logger.info(
                f"Loaded {len(self.packets)} packets from {self.pcap_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            return False

    def detect_deauth_flood(self, threshold: int = 10,
                            window_seconds: float = 1.0) -> list[dict[str, Any]]:
        """
        Detect Deauthentication flood attacks.

        Args:
            threshold: Number of deauth frames per window to trigger alert
            window_seconds: Time window in seconds

        Returns:
            List of alert dictionaries
        """
        if not self.loaded:
            self.load_pcap()

        alerts = []
        deauth_times = []

        for pkt in self.packets:
            if pkt.haslayer(Dot11Deauth):
                try:
                    timestamp = float(pkt.time)
                    deauth_times.append({
                        "time": timestamp,
                        "sender": pkt.addr2,
                        "target": pkt.addr1,
                        "reason": pkt[Dot11Deauth].reason
                    })
                except (AttributeError, TypeError, ValueError):
                    pass

        if not deauth_times:
            return []

        # Analyze for floods (many deauths in short window)
        deauth_times.sort(key=lambda x: x["time"])

        window_start = 0
        for i, d in enumerate(deauth_times):
            # Count deauths in current window
            window_count = 0
            for j in range(window_start, len(deauth_times)):
                if deauth_times[j]["time"] - d["time"] <= window_seconds:
                    window_count += 1
                else:
                    break

            if window_count >= threshold:
                alerts.append({
                    "type": "deauth_flood",
                    "severity": "CRITICAL",
                    "timestamp": datetime.fromtimestamp(d["time"]).isoformat(),
                    "count_in_window": window_count,
                    "threshold": threshold,
                    "sample_sender": d["sender"],
                    "sample_target": d["target"],
                    "message": f"Deauth flood detected: {window_count} frames in {window_seconds}s"
                })
                # Skip ahead to avoid duplicate alerts
                window_start = i + threshold
                if window_start >= len(deauth_times):
                    break

        return alerts

    def detect_evil_twin(
            self, known_networks: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect Evil Twin / Rogue AP attacks.
        An Evil Twin has same SSID but different BSSID/Encryption.

        Args:
            known_networks: Dict of SSID -> {bssid, encryption} for legitimate networks

        Returns:
            List of alert dictionaries
        """
        if not self.loaded:
            self.load_pcap()

        alerts = []
        seen_ssids = defaultdict(list)  # SSID -> list of (BSSID, Encryption)

        for pkt in self.packets:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                try:
                    bssid = pkt[Dot11].addr3
                    if not bssid:
                        continue

                    # Extract SSID
                    ssid = ""
                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 0:
                            ssid = elt.info.decode(
                                'utf-8', errors='ignore').strip('\x00')
                            break
                        elt = elt.payload.getlayer(Dot11Elt)

                    if ssid:
                        seen_ssids[ssid].append(bssid.upper())
                except (AttributeError, UnicodeDecodeError):
                    pass

        # Check against known networks
        for ssid, known_info in known_networks.items():
            known_bssid = known_info.get("bssid", "").upper()
            found_bssids = set(seen_ssids.get(ssid, []))

            for found_bssid in found_bssids:
                if found_bssid != known_bssid:
                    alerts.append({
                        "type": "evil_twin",
                        "severity": "HIGH",
                        "ssid": ssid,
                        "expected_bssid": known_bssid,
                        "detected_bssid": found_bssid,
                        "message": f"Potential Evil Twin: SSID '{ssid}' seen with unexpected BSSID {found_bssid}"
                    })

        return alerts

    def get_client_list(self) -> list[dict[str, Any]]:
        """
        Extract list of client devices from PCAP (Probe Requests).

        Returns:
            List of client info dictionaries
        """
        if not self.loaded:
            self.load_pcap()

        clients = {}

        for pkt in self.packets:
            if pkt.haslayer(Dot11):
                # Probe Request (type 0, subtype 4)
                if pkt.type == 0 and pkt.subtype == 4:
                    try:
                        client_mac = pkt.addr2
                        if client_mac and client_mac not in clients:
                            clients[client_mac] = {
                                "mac": client_mac.upper(),
                                "first_seen": datetime.fromtimestamp(
                                    float(
                                        pkt.time)).isoformat(),
                                "probed_ssids": []}

                        # Get probed SSID
                        elt = pkt.getlayer(Dot11Elt)
                        while elt:
                            if elt.ID == 0 and elt.info:
                                ssid = elt.info.decode(
                                    'utf-8', errors='ignore').strip('\x00')
                                if ssid and ssid not in clients[client_mac]["probed_ssids"]:
                                    clients[client_mac]["probed_ssids"].append(
                                        ssid)
                                break
                            elt = elt.payload.getlayer(Dot11Elt)
                    except (AttributeError, UnicodeDecodeError):
                        pass

        return list(clients.values())

    def generate_report(
            self, known_networks: Optional[dict] = None) -> dict[str, Any]:
        """
        Generate comprehensive forensic report.

        Args:
            known_networks: Optional dict of known legitimate networks

        Returns:
            Full report dictionary
        """
        if not self.loaded:
            self.load_pcap()

        report = {
            "pcap_file": self.pcap_path,
            "total_packets": len(self.packets),
            "analysis_time": datetime.now().isoformat(),
            "alerts": [],
            "clients": [],
            "summary": {}
        }

        # Run detections
        deauth_alerts = self.detect_deauth_flood()
        report["alerts"].extend(deauth_alerts)

        if known_networks:
            evil_twin_alerts = self.detect_evil_twin(known_networks)
            report["alerts"].extend(evil_twin_alerts)

        # Get clients
        report["clients"] = self.get_client_list()

        # Summary
        report["summary"] = {
            "total_alerts": len(
                report["alerts"]),
            "deauth_flood_detected": len(deauth_alerts) > 0,
            "evil_twin_detected": any(
                a["type"] == "evil_twin" for a in report["alerts"]),
            "unique_clients": len(
                report["clients"])}

        return report


def analyze_pcap(
        file_path: str, known_networks: Optional[dict] = None) -> dict[str, Any]:
    """
    Convenience function for quick PCAP analysis.

    Args:
        file_path: Path to PCAP file
        known_networks: Optional dict of known networks

    Returns:
        Forensic report dictionary
    """
    analyzer = ForensicAnalyzer(file_path)
    return analyzer.generate_report(known_networks)


if __name__ == "__main__":
    print("=" * 50)
    print("Forensic Analyzer Module Test")
    print("=" * 50)
    print("Usage: analyze_pcap('path/to/file.pcap')")
