import os
import sys
import unittest
from unittest.mock import patch

# Add root path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from lab_attack_service.attacks import LabSafetyChecker, LabSafetyConfig, LabSafetyError


class TestLabSafety(unittest.TestCase):
    def setUp(self):
        self.config = LabSafetyConfig(
            enabled=True,
            require_confirmation=False,  # Disable interactive confirm for tests
            allowed_bssid_prefixes=["00:11:22"],
            forbidden_bssid_prefixes=["AA:BB:CC"],
        )
        self.checker = LabSafetyChecker(self.config)

    def test_environment_check_fail(self):
        """Test that missing env var check raises error"""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(LabSafetyError):
                self.checker.check_environment()

    def test_environment_check_pass(self):
        """Test that correct env var passes check"""
        # Must include AUTH_KEY now
        with patch.dict(
            os.environ,
            {"SENTINEL_LAB_MODE": "true", "SENTINEL_AUTH_KEY": "valid_test_key"},
        ):
            self.assertTrue(self.checker.check_environment())

    def test_forbidden_prefix(self):
        """Test that forbidden BSSID prefix is blocked"""
        with self.assertRaises(LabSafetyError):
            self.checker.check_bssid("AA:BB:CC:11:22:33")

    def test_allowed_prefix(self):
        """Test that allowed BSSID prefix is accepted"""
        self.assertTrue(self.checker.check_bssid("00:11:22:33:44:55"))

    def test_unknown_prefix_blocked(self):
        """Test that unknown BSSID is blocked if allowed list is set"""
        with self.assertRaises(LabSafetyError):
            self.checker.check_bssid("11:22:33:44:55:66")

    def test_limit_check(self):
        """Test rate/count limiting"""
        with self.assertRaises(LabSafetyError):
            self.checker.check_count(1000, 100, "Deauth")


if __name__ == "__main__":
    unittest.main()
