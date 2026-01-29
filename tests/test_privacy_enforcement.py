import unittest

from sensor.normalizer import TelemetryNormalizer


# Mock parsed frame structure
class MockParsedFrame:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        # Add defaults for optional fields used in normalizer
        defaults = {
            "privacy": False,
            "ht_capable": False,
            "vht_capable": False,
            "he_capable": False,
            "pmf_capable": False,
            "pmf_required": False,
            "wps_enabled": False,
            "ess": False,
            "ibss": False,
            "ies_present": False,
            "rsn_info": None,
            "wpa_info": None,
            "beacon_interval": None,
            "ies": {},
            "rssi_dbm": -70,
            "channel": 1,
        }
        for k, v in defaults.items():
            if not hasattr(self, k):
                setattr(self, k, v)


# Import normalizer


class TestPrivacyEnforcement(unittest.TestCase):
    def test_store_raw_mac_false(self):
        """Verify that store_raw_mac=False results in hashed/anonymized MACs"""
        # MAC to test
        raw_mac = "AA:BB:CC:11:22:33"

        # Setup normalizer with privacy enabled
        # We explicitly pass store_raw_mac=False
        normalizer = TelemetryNormalizer(
            sensor_id="test_sensor", store_raw_mac=False, privacy_mode="anonymized"
        )

        # Mock a frame
        frame = MockParsedFrame(
            bssid=raw_mac,
            ssid="TestNet",
            channel=6,
            rssi_dbm=-50,
            timestamp=1234567890.0,
            frame_type="beacon",
            subtype=8,
        )

        # Normalize
        telemetry = normalizer.normalize(frame)

        # Check BSSID (should be anonymized)
        print(f"Original: {raw_mac}")
        print(f"Output:   {telemetry.bssid}")

        # Default behavior: Anonymize last 3 bytes
        expected_prefix = "AA:BB:CC"
        expected_suffix = "XX:XX:XX"

        self.assertTrue(
            telemetry.bssid.startswith(expected_prefix), "OUI should be preserved"
        )
        self.assertTrue(
            telemetry.bssid.endswith(expected_suffix), "Suffix should be anonymized"
        )
        self.assertNotEqual(telemetry.bssid, raw_mac, "MAC should not be raw")

        print("SUCCESS: MAC was modified correctly (Anonymized)")

    def test_store_raw_mac_true(self):
        """Verify that store_raw_mac=True keeps MAC raw"""
        raw_mac = "AA:BB:CC:11:22:33"
        normalizer = TelemetryNormalizer(sensor_id="test_sensor", store_raw_mac=True)
        frame = MockParsedFrame(bssid=raw_mac, ssid="TestNet", channel=1)
        telemetry = normalizer.normalize(frame)

        self.assertEqual(telemetry.bssid, raw_mac, "MAC should remain raw")
        print("SUCCESS: MAC was preserved when allowed")


if __name__ == "__main__":
    unittest.main()
