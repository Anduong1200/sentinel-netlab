#!/usr/bin/env python3
"""
Unit tests for WiFi Scanner Sensor modules
"""

import os
import sys
import unittest

# Add sensor to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sensor"))


class TestRiskScoring(unittest.TestCase):
    """Test risk scoring module"""

    def setUp(self):
        from risk import RiskScorer

        self.scorer = RiskScorer()

    def test_open_network_high_risk(self):
        """Open networks should have high risk"""
        network = {
            "ssid": "Free_WiFi",
            "bssid": "AA:BB:CC:11:22:33",
            "encryption": "Open",
            "signal": -50,
            "channel": 6,
        }
        result = self.scorer.calculate_risk(network)
        self.assertGreaterEqual(result["risk_score"], 70)

    def test_wpa3_low_risk(self):
        """WPA3 networks should have lower risk"""
        network = {
            "ssid": "Secure_Home",
            "bssid": "AA:BB:CC:44:55:66",
            "encryption": "WPA3-SAE",
            "signal": -70,
            "channel": 11,
        }
        result = self.scorer.calculate_risk(network)
        self.assertLess(result["risk_score"], 50)

    def test_score_range(self):
        """Score should be between 0 and 100"""
        network = {
            "ssid": "Test",
            "bssid": "11:22:33:44:55:66",
            "encryption": "WPA2",
            "signal": -60,
            "channel": 1,
        }
        result = self.scorer.calculate_risk(network)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


class TestParser(unittest.TestCase):
    """Test parser module"""

    def setUp(self):
        from parser import WiFiParser

        self.parser = WiFiParser()

    def test_vendor_lookup(self):
        """Test OUI vendor lookup"""
        # TP-Link OUI
        vendor = self.parser.get_vendor("TP:LI:NK:11:22:33")
        # Should return something (might be Unknown if not in DB)
        self.assertIsInstance(vendor, str)

    def test_unknown_vendor(self):
        """Unknown OUI should return 'Unknown'"""
        vendor = self.parser.get_vendor("00:00:00:00:00:00")
        self.assertEqual(vendor, "Unknown")


class TestStorage(unittest.TestCase):
    """Test storage module (in-memory only)"""

    def setUp(self):
        from storage import MemoryStorage

        self.storage = MemoryStorage()

    def test_add_network(self):
        """Test adding a network"""
        network = {"ssid": "Test", "bssid": "AA:BB:CC:DD:EE:FF"}
        self.storage.update(network)
        self.assertEqual(self.storage.count(), 1)

    def test_update_network(self):
        """Test updating existing network"""
        network = {"ssid": "Test", "bssid": "AA:BB:CC:DD:EE:FF", "signal": -60}
        self.storage.update(network)

        # Update with new signal
        network["signal"] = -50
        self.storage.update(network)

        # Should still be 1 network
        self.assertEqual(self.storage.count(), 1)

    def test_clear(self):
        """Test clearing storage"""
        self.storage.update({"ssid": "Test", "bssid": "11:22:33:44:55:66"})
        self.storage.clear()
        self.assertEqual(self.storage.count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
