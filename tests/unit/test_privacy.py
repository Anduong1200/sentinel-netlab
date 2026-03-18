import unittest
import os
from unittest.mock import patch
import common.privacy as privacy

class TestPrivacy(unittest.TestCase):
    def setUp(self):
        # Reset the global salt before each test
        privacy._PRIVACY_SALT = None

    def test_get_privacy_salt_generated(self):
        """Verify that a 16-character hex salt is generated when no env var exists"""
        with patch.dict(os.environ, {}, clear=True):
            salt = privacy.get_privacy_salt()
            self.assertEqual(len(salt), 32)  # secrets.token_hex(16) -> 32 chars
            self.assertTrue(all(c in "0123456789abcdef" for c in salt))

    def test_get_privacy_salt_from_env(self):
        """Verify that PRIVACY_SALT env var is used when set"""
        test_salt = "test-salt-12345"
        with patch.dict(os.environ, {"PRIVACY_SALT": test_salt}):
            salt = privacy.get_privacy_salt()
            self.assertEqual(salt, test_salt)

    def test_get_privacy_salt_cached(self):
        """Verify that the salt is cached and does not change on subsequent calls"""
        with patch.dict(os.environ, {}, clear=True):
            salt1 = privacy.get_privacy_salt()
            salt2 = privacy.get_privacy_salt()
            self.assertEqual(salt1, salt2)

            # Change environment - should still use cached salt
            with patch.dict(os.environ, {"PRIVACY_SALT": "new-salt"}):
                salt3 = privacy.get_privacy_salt()
                self.assertEqual(salt1, salt3)

    def test_normalize_mac(self):
        """Verify normalization across various MAC formats"""
        test_cases = [
            ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"),
            ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
            ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
            ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),
            ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
            ("AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"),
        ]
        for input_mac, expected_mac in test_cases:
            with self.subTest(input_mac=input_mac):
                self.assertEqual(privacy.normalize_mac(input_mac), expected_mac)

    def test_get_oui(self):
        """Verify extraction of the OUI (first 3 octets)"""
        self.assertEqual(privacy.get_oui("AA:BB:CC:DD:EE:FF"), "AA:BB:CC")
        self.assertEqual(privacy.get_oui("aa-bb-cc-dd-ee-ff"), "AA:BB:CC")

    def test_hash_mac(self):
        """Verify MAC hashing returns a 16-character hex string"""
        mac = "AA:BB:CC:11:22:33"
        salt = "testsalt"
        h1 = privacy.hash_mac(mac, salt)
        self.assertEqual(len(h1), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in h1))

        # Consistent output
        h2 = privacy.hash_mac(mac, salt)
        self.assertEqual(h1, h2)

        # Different MAC -> Different hash
        h3 = privacy.hash_mac("AA:BB:CC:11:22:34", salt)
        self.assertNotEqual(h1, h3)

    def test_anonymize_mac_oui(self):
        """Verify OUI anonymization (replaces last 3 bytes with 00)"""
        mac = "AA:BB:CC:11:22:33"
        self.assertEqual(privacy.anonymize_mac_oui(mac), "AA:BB:CC:00:00:00")

    def test_anonymize_mac_full(self):
        """Verify full MAC anonymization (hashed appearance)"""
        mac = "AA:BB:CC:11:22:33"
        anonymized = privacy.anonymize_mac_full(mac)
        # Should look like a MAC
        import re
        self.assertTrue(re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", anonymized))
        self.assertNotEqual(anonymized, mac)

    def test_anonymize_mac_dispatcher(self):
        """Verify anonymize_mac dispatcher function"""
        mac = "AA:BB:CC:11:22:33"
        # OUI mode
        self.assertEqual(privacy.anonymize_mac(mac, mode="oui"), "AA:BB:CC:00:00:00")
        # Full mode
        full = privacy.anonymize_mac(mac, mode="full")
        self.assertNotEqual(full, mac)
        self.assertTrue(":" in full)
        # Fallback
        fallback = privacy.anonymize_mac(mac, mode="invalid")
        self.assertEqual(fallback, privacy.anonymize_mac_full(mac))

    def test_anonymize_ssid(self):
        """Verify SSID anonymization"""
        ssid = "MyWiFiNetwork"
        # Keep length (asterisks)
        self.assertEqual(privacy.anonymize_ssid(ssid, keep_length=True), "*" * len(ssid))
        # Hash SSID
        h_ssid = privacy.anonymize_ssid(ssid, keep_length=False)
        self.assertTrue(h_ssid.endswith("..."))
        self.assertEqual(len(h_ssid), 8 + 3)

        # Empty SSID
        self.assertEqual(privacy.anonymize_ssid(""), "")

if __name__ == "__main__":
    unittest.main()
