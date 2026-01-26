from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
import logging
import json

logger = logging.getLogger(__name__)

class PacketHandler:
    def __init__(self):
        self.networks = {}  # Store unique networks: {bssid: data}

    def process_packet(self, packet):
        """Callback function for scapy sniffer"""
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._extract_network_info(packet)

    def _extract_network_info(self, packet):
        try:
            bssid = packet[Dot11].addr3
            
            # Simple deduplication based on BSSID
            # Note: In a real scan, we might want to update RSSI if signals fluctuate
            
            ssid = "Hidden Network"
            try: 
                # SSID is usually Element ID 0
                ssid_elt = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                if ssid_elt:
                    ssid = ssid_elt
            except:
                pass

            # RSSI Extraction from RadioTap header
            rssi = -100
            if packet.haslayer(RadioTap):
                # Check for standard dBm_AntSignal field
                # Note: Scapy RadioTap parsing can be tricky depending on driver
                try:
                    rssi = packet[RadioTap].dBm_AntSignal
                except:
                    pass

            # Encryption Detection capabilities
            encryption = []
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            
            # Check capabilities
            if "privacy" in cap:
                encryption.append("WEP/WPA")
                # Further analysis would require parsing RSN/WPA tags (Element ID 48/221)
                # For basic PoC, we assume if privacy bit is set, it's secured.
                # Use robust checking via IE tags for WPA2/WPA3 in full version.
                
                # Basic IE check
                elt = packet[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 48: # RSN (WPA2)
                        encryption.append("WPA2")
                        if "WEP/WPA" in encryption: encryption.remove("WEP/WPA")
                    elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01'): # Vendor Specific (WPA1)
                        encryption.append("WPA")
                        if "WEP/WPA" in encryption: encryption.remove("WEP/WPA")
                    elt = elt.payload
            else:
                encryption.append("OPEN")

            network_data = {
                "ssid": ssid,
                "bssid": bssid,
                "rssi": int(rssi),
                "encryption": "/".join(list(set(encryption))), # Clean up duplicates
                "channel": 0 # Placeholder, hard to get accurate channel from frame sometimes
            }
            
            # Try to get channel from DS Set (ID 3)
            try:
                elt = packet[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 3:
                        network_data["channel"] = int(ord(elt.info))
                        break
                    elt = elt.payload
            except:
                pass

            self.networks[bssid] = network_data
            
        except Exception as e:
            logger.debug(f"Packet parse error: {e}")

    def get_networks(self):
        """Return list of discovered networks"""
        return list(self.networks.values())

    def clear(self):
        self.networks = {}
