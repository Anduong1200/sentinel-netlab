"""
Feature Extraction Module for Wireless Risk Analysis.
Transforms raw network metadata into normalized numerical feature vectors (0.0 to 1.0).
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts features from network dictionaries for use in Risk Scoring or ML.
    """

    def __init__(self, config: dict[str, Any] = None):
        self.config = config or {}
        self.mappings = self.config.get("feature_mappings", {})

        # Default patterns if not in config
        self.suspicious_ssid_patterns = [
            r"free",
            r"guest",
            r"public",
            r"open",
            r"linksys",
            r"netgear",
            r"default",
            r"test",
        ]

        self.trusted_vendors = [
            "cisco",
            "aruba",
            "juniper",
            "fortinet",
            "meraki",
            "ruckus",
        ]

    def extract(self, network: dict[str, Any]) -> dict[str, float]:
        """
        Main extraction entry point.
        Returns a dictionary of normalized float features.
        """
        features = {}

        features["enc_score"] = self._extract_encryption(network)
        features["rssi_norm"] = self._extract_rssi(network)
        features["vendor_trust"] = self._extract_vendor(network)
        features["ssid_suspicious"] = self._extract_ssid_suspicion(network)
        features["ssid_hidden"] = (
            1.0 if not network.get("ssid") or network.get("ssid") == "<hidden>" else 0.0
        )
        features["wps_flag"] = 1.0 if network.get("wps_enabled") or network.get("wps") else 0.0
        features["channel_unusual"] = self._extract_channel(network)
        features["beacon_anomaly"] = self._extract_beacon_anomaly(network)
        features["temporal_new"] = self._extract_temporal(network)
        features["privacy_concern"] = self._extract_privacy(network)

        return features

    def _extract_encryption(self, network: dict) -> float:
        enc_str = str(network.get("encryption", "OPEN")).upper()
        mapping = self.mappings.get("encryption", {})

        # Default logic if mapping missing or partial
        if "WPA3" in enc_str:
            return mapping.get("WPA3", 0.0)
        if "TKIP" in enc_str:
            return mapping.get("TKIP", 0.4)
        if "WPA2" in enc_str:
            return mapping.get("WPA2", 0.2)
        if "WPA" in enc_str:
            return mapping.get("WPA", 0.5)
        if "WEP" in enc_str:
            return mapping.get("WEP", 0.9)
        return mapping.get("OPEN", 1.0)

    def _extract_rssi(self, network: dict) -> float:
        try:
            rssi = float(network.get("signal", -100))
        except (ValueError, TypeError):
            rssi = -100.0

        # Normalize -100 (weak) to -50 (strong) -> 0.0 to 1.0
        # Formula: clamp((RSSI + 100) / 50, 0, 1)
        # -100 + 100 = 0 / 50 = 0
        # -50 + 100 = 50 / 50 = 1
        val = (rssi + 100.0) / 50.0
        return max(0.0, min(1.0, val))

    def _extract_vendor(self, network: dict) -> float:
        vendor = str(network.get("vendor", "")).lower()
        if not vendor or vendor == "unknown":
            return 0.5

        if any(v in vendor for v in self.trusted_vendors):
            return 0.0  # Trusted

        return 0.3  # Consumer/Common

    def _extract_ssid_suspicion(self, network: dict) -> float:
        ssid = str(network.get("ssid", "")).lower()
        if not ssid:
            return 0.0

        for pattern in self.suspicious_ssid_patterns:
            if re.search(pattern, ssid):
                return 1.0  # Matched suspicious pattern
        return 0.0

    def _extract_channel(self, network: dict) -> float:
        try:
            ch = int(network.get("channel", 0))
        except (ValueError, TypeError):
            ch = 0

        # Common 2.4GHz channels
        if ch in [1, 6, 11]:
            return 0.0
        # Other valid channels
        if 1 <= ch <= 14:
            return 0.3
        # 5GHz (simplified for now, treat as trusted/low risk compared to weird
        # 2.4 channels)
        if ch > 14:
            return 0.1
        return 0.5  # Unknown

    def _extract_beacon_anomaly(self, network: dict) -> float:
        # Placeholder for real anomaly detection logic
        # Here we just look at Beacon Interval deviation if available
        # Standard is often 100 TU (102.4 ms)
        bi = network.get("beacon_interval")
        if bi:
            try:
                bi = float(bi)
                # deviation from 102400 (microseconds)
                std_bi = 102400
                diff = abs(bi - std_bi)
                if diff > 1000:  # significant deviation
                    return 1.0
            except (ValueError, TypeError):
                pass
        return 0.0

    def _extract_temporal(self, network: dict) -> float:
        # If first_seen == last_seen (within small delta), it's new
        # This requires formatted timestamp string parsing or raw timestamp usage
        # Assuming timestamps are strings, we simplisticly check equality
        fs = network.get("first_seen")
        ls = network.get("last_seen")
        if fs and ls and fs == ls:
            return 0.5
        return 0.0

    def _extract_privacy(self, network: dict) -> float:
        caps = str(network.get("capabilities", ""))
        score = 0.0
        if "ESS" not in caps:
            score += 0.3
        if network.get("wps_enabled"):
            score += 0.2
        return min(1.0, score)
