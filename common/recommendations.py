"""
Recommendation Engine
Generates actionable advice based on risk scores and detection flags.
Algorithm: Rule-based Expert System
"""

from typing import Any


class RecommendationEngine:
    """
    Expert system for generating security recommendations.
    """

    @staticmethod
    def analyze(network_data: dict[str, Any], risk_result: dict[str, Any]) -> list[str]:
        """
        Generate recommendations list based on network state and risk.

        Args:
            network_data: Raw network dictionary (ssid, encryption, etc.)
            risk_result: Output from RiskScorer (risk_score, features, etc.)

        Returns:
            List of strings (recommendations)
        """
        recs = []
        features = risk_result.get("features", {})

        # 1. Critical Threats (Attacks)
        if network_data.get("is_evil_twin"):
            recs.append(
                "CRITICAL: Detect Evil Twin attack. Disconnect immediately and verify AP MAC address."
            )

        # 2. Encryption Issues
        enc = network_data.get("encryption", "Unknown").upper()
        if "OPEN" in enc or features.get("enc_score", 0) > 0.8:
            recs.append(
                "Critical: Open network detected. Use VPN for all traffic. Do not access sensitive banking/email."
            )
        elif "WEP" in enc:
            recs.append(
                "High Risk: WEP is broken. Upgrade router to WPA2/WPA3 immediately."
            )
        elif "WPA" in enc and "WPA2" not in enc and "WPA3" not in enc:
            recs.append("Medium Risk: WPA1 is deprecated. Upgrade to WPA2/AES.")

        # 3. Router Configuration
        if network_data.get("wps_enabled"):
            recs.append(
                "hardening: Disable WPS (WiFi Protected Setup) to prevent PIN brute-force."
            )

        if (
            "Default" in network_data.get("ssid", "")
            or features.get("ssid_suspicious", 0) > 0.5
        ):
            recs.append(
                "hardening: Change default SSID (network name) to reduce targeting profile."
            )

        # 4. Signal/Location
        if features.get("rssi_norm", 0) > 0.9 and risk_result.get("risk_score", 0) > 70:
            recs.append(
                "Physical Security: High-risk AP is in close proximity. Check for rogue devices nearby."
            )

        # 5. General Advice based on Score
        score = risk_result.get("risk_score", 0)
        if score > 80:
            recs.append("Action: Perform full security audit of this network.")
        elif score > 50:
            recs.append("Action: Monitor network for suspicious clients.")

        return recs


def generate_recommendations(network: dict, risk_result: dict) -> list[str]:
    """Helper wrapper"""
    return RecommendationEngine.analyze(network, risk_result)
