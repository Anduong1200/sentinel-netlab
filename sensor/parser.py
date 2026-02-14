#!/usr/bin/env python3
"""
WiFi Parser Module - 802.11 frame parsing and network extraction
Parses Beacon and Probe Response frames to extract network information
"""

import logging
from datetime import UTC, datetime
from typing import Any

try:
    from scapy.all import (
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeResp,
        RadioTap,
    )

    SCAPY_AVAILABLE = True
except (ImportError, OSError):
    SCAPY_AVAILABLE = False
    # Define dummy classes for type hints and avoid NameError
    Dot11 = Any
    Dot11Beacon = Any
    Dot11Deauth = Any
    Dot11Elt = Any
    Dot11ProbeResp = Any
    RadioTap = Any

logger = logging.getLogger(__name__)


# OUI Database (partial - common vendors)
# OUI Database moved to common.oui
try:
    from common.oui import get_vendor as common_get_vendor
except ImportError:
    # Fallback if common not found (e.g. running standalone)
    common_get_vendor = None


class WiFiParser:
    """
    Parses 802.11 management frames and extracts network information.
    """

    # Encryption detection values
    CIPHER_SUITES = {
        0x01: "WEP-40",
        0x02: "TKIP",
        0x04: "CCMP",
        0x05: "WEP-104",
    }

    AUTH_SUITES = {
        0x01: "802.1X",  # WPA Enterprise
        0x02: "PSK",  # WPA Personal
    }

    def __init__(self):
        """Initialize the parser with an empty networks dictionary."""
        self.networks: dict[str, dict[str, Any]] = {}
        # Deauth, Evil Twin events
        self.security_events: list[dict[str, Any]] = []
        self.packet_count = 0
        self.last_update = datetime.now(UTC)

    def get_vendor(self, mac: str) -> str:
        """
        Look up vendor name from MAC address OUI.

        Args:
            mac: MAC address in format XX:XX:XX:XX:XX:XX

        Returns:
            Vendor name or "Unknown"
        """
        if common_get_vendor:
            return common_get_vendor(mac)

        if not mac:
            return "Unknown"
        # Fallback empty logic if import failed
        return "Unknown"

    def parse_encryption(self, packet) -> str:
        """
        Parse encryption type from beacon/probe response.

        Returns:
            String describing encryption (e.g., "WPA2-PSK", "WEP", "Open")
        """
        if not SCAPY_AVAILABLE:
            return "Unknown"

        if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeResp):
            return "Unknown"

        # Get capability info
        cap = packet.sprintf(
            "{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}"
        )

        # Check for WPA/WPA2/WPA3
        encryption = "Open"
        crypto = set()

        # Parse information elements
        elt = packet.getlayer(Dot11Elt)
        while elt:
            # RSN (WPA2)
            if elt.ID == 48:
                encryption = "WPA2"
                try:
                    # Parse RSN info for auth type
                    if b"\x00\x0f\xac\x02" in elt.info:
                        crypto.add("PSK")
                    if b"\x00\x0f\xac\x01" in elt.info:
                        crypto.add("802.1X")
                    # Check for SAE (WPA3)
                    if b"\x00\x0f\xac\x08" in elt.info:
                        encryption = "WPA3"
                        crypto.add("SAE")
                except (AttributeError, IndexError):
                    pass

            # WPA (vendor specific)
            elif elt.ID == 221:
                if elt.info.startswith(b"\x00\x50\xf2\x01"):
                    if encryption == "Open":
                        encryption = "WPA"
                    crypto.add("TKIP")

            elt = elt.payload.getlayer(Dot11Elt)

        # Check for WEP
        if "privacy" in cap and encryption == "Open":
            encryption = "WEP"

        # Combine encryption and auth
        if crypto:
            return f"{encryption}-{'/'.join(sorted(crypto))}"

        return encryption

    def parse_channel(self, packet) -> int:
        """Extract channel from RadioTap or DS Parameter Set."""
        # Try RadioTap first
        if packet.haslayer(RadioTap):
            try:
                return packet[RadioTap].Channel
            except (AttributeError, TypeError):
                pass

        # Try DS Parameter Set
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:  # DS Parameter Set
                return int(elt.info[0])
            elt = elt.payload.getlayer(Dot11Elt)

        return 0

    def parse_rssi(self, packet) -> int:
        """Extract RSSI from RadioTap header."""
        if packet.haslayer(RadioTap):
            try:
                # Try dBm_AntSignal first
                rssi = packet[RadioTap].dBm_AntSignal
                if rssi is not None:
                    return int(rssi)
            except (AttributeError, TypeError, ValueError):
                pass
        return -100  # Default weak signal

    def parse_deauth(self, packet) -> dict[str, Any] | None:
        """
        Parse Deauthentication frame to detect potential attack.

        Args:
            packet: Scapy packet with Dot11Deauth layer

        Returns:
            Security event dictionary if Deauth detected
        """
        if not packet.haslayer(Dot11Deauth):
            return None

        try:
            reason = packet[Dot11Deauth].reason
            sender = packet.addr2  # Usually AP or Attacker spoofing AP
            target = packet.addr1  # Victim
            bssid = packet.addr3  # AP

            # Common attack reasons: 7 (Class 3 frame from nonassociated STA)
            is_suspicious = reason in [7, 1, 4, 5, 6, 8]

            event = {
                "type": "deauth_detected",
                "sender": sender,
                "target": target,
                "bssid": bssid,
                "reason_code": reason,
                "timestamp": datetime.now(UTC).isoformat(),
                "severity": "HIGH" if is_suspicious else "INFO",
            }
            return event
        except Exception as e:
            logger.debug(f"Error parsing deauth: {e}")
            return None

    def process_packet(self, packet) -> dict[str, Any] | None:
        """
        Process a captured 802.11 packet and extract network info.

        Args:
            packet: Scapy packet object

        Returns:
            Network dictionary if valid beacon/probe, None otherwise
        """
        if not SCAPY_AVAILABLE:
            return None

        self.packet_count += 1

        if not packet.haslayer(Dot11):
            return None

        # Check for Deauthentication (Management frame subtype 12)
        if packet.type == 0 and packet.subtype == 12:
            deauth_event = self.parse_deauth(packet)
            if deauth_event:
                self.security_events.append(deauth_event)
                logger.warning(
                    f"Deauth detected: {deauth_event['sender']} -> {deauth_event['target']}"
                )
                return deauth_event

        # Check for EAPOL (Handshake)
        # 0x888e is EAPOL. Scapy usually decodes content as EAPOL layer.
        if packet.type == 2 and packet.haslayer("EAPOL"):
            try:
                # For EAPOL, addr3 is usually BSSID in infrastructure mode
                bssid = packet.addr3
                if bssid and bssid in self.networks:
                    self.networks[bssid]["handshake_captured"] = True
                    logger.info(
                        f"Handshake captured for {self.networks[bssid]['ssid']}"
                    )
                    return self.networks[bssid]
            except Exception:  # nosec B110
                pass
            return None

        # Only parse Beacons/ProbeResp for network discovery
        if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            return None

        try:
            # Extract BSSID
            bssid = packet[Dot11].addr3
            if not bssid or bssid.lower() == "ff:ff:ff:ff:ff:ff":
                return None

            bssid = bssid.upper()

            # Extract SSID
            ssid = ""
            elt = packet.getlayer(Dot11Elt)
            wps_present = False

            while elt:
                # SSID
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode("utf-8", errors="ignore").strip("\x00")
                    except (UnicodeDecodeError, AttributeError):
                        ssid = ""

                # Check for WPS (Vendor Specific ID 221 + Microsoft OUI
                # \x00\x50\xf2\x04)
                elif elt.ID == 221:
                    if elt.info.startswith(b"\x00\x50\xf2\x04"):
                        wps_present = True

                elt = elt.payload.getlayer(Dot11Elt)

            # Extract other info
            channel = self.parse_channel(packet)
            rssi = self.parse_rssi(packet)
            encryption = self.parse_encryption(packet)
            vendor = self.get_vendor(bssid)

            now = datetime.now(UTC)

            # Update or create network entry
            if bssid in self.networks:
                network = self.networks[bssid]
                network["last_seen"] = now.isoformat()
                network["beacon_count"] = network.get("beacon_count", 0) + 1
                network["rssi"] = rssi
                if wps_present:
                    network["wps"] = True
                if channel > 0:
                    network["channel"] = channel
            else:
                network = {
                    "ssid": ssid or "<Hidden>",
                    "bssid": bssid,
                    "channel": channel,
                    "rssi": rssi,
                    "encryption": encryption,
                    "vendor": vendor,
                    "first_seen": now.isoformat(),
                    "last_seen": now.isoformat(),
                    "beacon_count": 1,
                    "wps": wps_present,
                    "handshake_captured": False,
                }
                self.networks[bssid] = network

            self.last_update = now
            return network

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    def get_networks(self) -> list[dict[str, Any]]:
        """
        Get all discovered networks as a list.

        Returns:
            List of network dictionaries
        """
        return list(self.networks.values())

    def get_network_count(self) -> int:
        """Get count of unique networks discovered."""
        return len(self.networks)

    def clear(self):
        """Clear all discovered networks."""
        self.networks.clear()
        self.packet_count = 0
        logger.info("Parser cleared")

    def get_stats(self) -> dict[str, Any]:
        """Get parser statistics."""
        handshake_count = sum(
            1 for n in self.networks.values() if n.get("handshake_captured")
        )
        return {
            "network_count": len(self.networks),
            "packet_count": self.packet_count,
            "handshake_count": handshake_count,
            "last_update": self.last_update.isoformat(),
            "encryption_summary": self._get_encryption_summary(),
        }

    def _get_encryption_summary(self) -> dict[str, int]:
        """Count networks by encryption type."""
        summary: dict[str, int] = {}
        for network in self.networks.values():
            enc = network.get("encryption", "Unknown")
            # Simplify to base type
            base_enc = enc.split("-")[0]
            summary[base_enc] = summary.get(base_enc, 0) + 1
        return summary


# Convenience function for parsing a single packet
def parse_beacon(packet) -> dict[str, Any] | None:
    """
    Parse a single beacon/probe response packet.

    Args:
        packet: Scapy packet object

    Returns:
        Network dictionary or None
    """
    parser = WiFiParser()
    return parser.process_packet(packet)


if __name__ == "__main__":
    # Test with sample data
    print("=" * 50)
    print("WiFi Parser Module Test")
    print("=" * 50)

    parser = WiFiParser()

    # Test vendor lookup
    test_macs = [
        "B8:27:EB:12:34:56",  # Raspberry Pi
        "14:CF:E2:AB:CD:EF",  # Apple
        "FF:FF:FF:FF:FF:FF",  # Unknown
    ]

    for mac in test_macs:
        vendor = parser.get_vendor(mac)
        print(f"MAC: {mac} -> Vendor: {vendor}")

    print(f"\nPacket count: {parser.packet_count}")
    print(f"Network count: {parser.get_network_count()}")
