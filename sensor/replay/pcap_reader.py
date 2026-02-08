import logging
from collections.abc import Generator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PcapStream:
    """
    Reads a PCAP file and yields normalized telemetry events.
    Simulates the "Capture -> Normalize" phase of the Sensor.
    """

    def __init__(self, pcap_path: Path):
        self.pcap_path = pcap_path

    def stream(self) -> Generator[dict[str, Any], None, None]:
        """Yields telemetry dicts."""
        try:
            from scapy.all import (  # type: ignore
                Dot11,
                Dot11Beacon,
                Dot11Elt,
                PcapReader,
                RadioTap,
            )
        except ImportError:
            logger.error("Scapy not installed. Cannot replay PCAP.")
            return

        try:
            with PcapReader(str(self.pcap_path)) as reader:
                for pkt in reader:
                    if not pkt.haslayer(Dot11Beacon):
                        continue

                    # Normalize (Simplified logic from wardrive.py)
                    try:
                        ssid = "<Hidden>"
                        if pkt.haslayer(Dot11Elt):
                            # Iterate elements to find SSID (ID 0)
                            # Scapy's Dot11Elt structure is a bit complex to iterate perfectly without looping
                            # Simplified: .info is usually the first element (SSID) if standard beacon
                            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")

                        bssid = pkt[Dot11].addr2

                        rssi = -100
                        if pkt.haslayer(RadioTap):
                            rssi = pkt[RadioTap].dBm_AntSignal

                        # Security (Simplified)
                        security = "Open"
                        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                        if "privacy" in cap:
                            security = "WPA2"  # Generic enc assumption

                        # Channel
                        channel = 0
                        # Extract channel from Elt ID 3? Too complex for this snippet.
                        # Assume mocked/default for now or extraction logic if critical.
                        # Let's try basic extraction if possible, else 0.

                        yield {
                            "ssid": ssid,
                            "bssid": bssid,
                            "security": security,
                            "rssi_dbm": int(rssi),
                            "channel": channel,
                            "timestamp": pkt.time,
                        }
                    except Exception as e:
                        logger.warning(f"Failed to parse packet: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error reading PCAP {self.pcap_path}: {e}")
