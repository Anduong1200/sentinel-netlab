#!/usr/bin/env python3
"""
Unit tests for Active Pentest & Risk Upgrade
"""

import unittest
import sys
import os
from unittest.mock import MagicMock

# Add sensor to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sensor'))

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Ether, EAPOL

class TestActiveFeatures(unittest.TestCase):
    
    def setUp(self):
        from parser import WiFiParser
        from risk import RiskScorer
        self.parser = WiFiParser()
        self.scorer = RiskScorer()

    def test_wps_detection(self):
        """Test if parser detects WPS IE (221)"""
        # Create a mock Beacon with WPS IE
        # IE 221, Len, OUI (Microsoft: 00 50 f2 04)
        wps_ie = Dot11Elt(ID=221, info=b'\x00\x50\xf2\x04\x00\x01\x00')
        packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="AA:BB:CC:11:22:33", addr3="AA:BB:CC:11:22:33") / Dot11Beacon() / Dot11Elt(ID=0, info="WPS_Net") / wps_ie
        
        net = self.parser.process_packet(packet)
        self.assertTrue(net.get("wps"), "WPS detection failed")
        
    def test_risk_wps_penalty(self):
        """Test if WPS enabled increases risk score"""
        # Mock network with WPS
        net = {
            "ssid": "WPS_Net",
            "bssid": "AA:BB:CC:11:22:33",
            "encryption": "WPA2-PSK",
            "wps": True,
            "rssi": -50,
            "vendor": "Test"
        }
        
        result = self.scorer.calculate_risk(net)
        # Factor Score for WPS is 100, Weight 0.20 -> +20 points
        # WPA2-PSK (20) * 0.40 = 8
        # RSSI (-50->60) * 0.10 = 6
        # Vendor (Known->10) * 0.05 = 0.5
        # SSID (Normal->10) * 0.10 = 1
        # Total approx: 20 + 8 + 6 + 0.5 + 1 = 35.5 -> 36?
        # Wait, Signal is 0.10. SSID 0.10. 
        # Let's check the factors in result
        wps_factor = next(f for f in result["factors"] if f["name"] == "wps")
        self.assertEqual(wps_factor["score"], 100)
        self.assertEqual(wps_factor["weight"], 0.20)
        
    def test_risk_handshake_penalty(self):
        """Test if captured handshake increases risk score"""
        # Mock network with Handshake
        net = {
            "ssid": "Target_Net",
            "bssid": "11:22:33:44:55:66",
            "encryption": "WPA2-PSK",
            "handshake_captured": True
        }
        
        result = self.scorer.calculate_risk(net)
        traffic_factor = next(f for f in result["factors"] if f["name"] == "traffic")
        self.assertEqual(traffic_factor["score"], 100)
        self.assertEqual(traffic_factor["weight"], 0.15)

    def test_encryption_tkip_penalty(self):
        """Test WPA2-TKIP vs WPA2-AES scoring"""
        net_tkip = {"ssid": "T", "encryption": "WPA2-TKIP", "wps": False}
        net_aes = {"ssid": "A", "encryption": "WPA2-CCMP", "wps": False}
        
        score_tkip = self.scorer.calculate_risk(net_tkip)["risk_score"]
        score_aes = self.scorer.calculate_risk(net_aes)["risk_score"]
        
        # TKIP factor score 40 * 0.40 = 16
        # AES/CCMP factor score 20 * 0.40 = 8
        # Plus other base scores (Signal -100 -> 10 * 0.1 = 1, etc.)
        self.assertGreater(score_tkip, score_aes, "TKIP should have higher risk score than CCMP")

if __name__ == '__main__':
    unittest.main()
