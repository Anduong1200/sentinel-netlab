#!/usr/bin/env python3
"""
WiFi Risk Scoring Module - Security risk assessment for wireless networks
Calculates risk scores based on encryption, signal strength, and other factors
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level categories."""
    CRITICAL = "critical"  # 90-100
    HIGH = "high"          # 70-89
    MEDIUM = "medium"      # 40-69
    LOW = "low"            # 0-39


@dataclass
class RiskFactor:
    """Individual risk factor with weight and score."""
    name: str
    weight: float  # 0.0 - 1.0
    score: int     # 0 - 100
    description: str


class RiskScorer:
    """
    Calculates security risk scores for wireless networks.
    
    Score range: 0 (safest) to 100 (most risky)
    """
    
    # Weight distribution (should sum to 1.0)
    WEIGHTS = {
        "encryption": 0.40,      # Encryption strength
        "wps": 0.20,             # WPS Vulnerability
        "traffic": 0.15,         # Active traffic/Handshake
        "ssid_analysis": 0.10,   # Suspicious names
        "signal_strength": 0.10, # Proximity
        "vendor": 0.05,          # Vendor reputation
    }
    
    # Encryption risk scores (higher = more risky)
    ENCRYPTION_SCORES = {
        "Open": 100,
        "WEP": 95,
        "WEP-40": 95,
        "WEP-104": 90,
        "WPA": 60,
        "WPA-TKIP": 55,
        "WPA-PSK": 50,
        "WPA2": 20,          # Standard
        "WPA2-CCMP": 20,     # Standard
        "WPA2-TKIP": 40,     # Weak cipher
        "WPA2-PSK2": 20,
        "WPA2-802.1X": 15,
        "WPA3": 10,
        "WPA3-SAE": 5,
    }
    
    # Suspicious SSID patterns
    SUSPICIOUS_SSID_PATTERNS = [
        "free",
        "wifi",
        "hotspot",
        "guest",
        "public",
        "open",
        "test",
        "hack",
        "evil",
        "twin",
    ]
    
    # Known vulnerable/suspicious vendor patterns
    SUSPICIOUS_VENDORS = [
        "unknown",
        "test",
        "virtual",
    ]
    
    def __init__(self):
        """Initialize the risk scorer."""
        pass

    def calculate_wps_score(self, wps_enabled: bool) -> RiskFactor:
        """
        Calculate risk based on WPS status.
        WPS is vulnerable to brute-force and Pixie Dust attacks.
        
        Args:
            wps_enabled: True if WPS is detected
            
        Returns:
            RiskFactor
        """
        if wps_enabled:
            return RiskFactor(
                name="wps",
                weight=self.WEIGHTS["wps"],
                score=100,  # Critical vulnerability (High Factor Score)
                description="WPS Enabled (Vulnerable to Pixie Dust/Brute Force)"
            )
        return RiskFactor(
            name="wps",
            weight=self.WEIGHTS["wps"],
            score=0,
            description="WPS Disabled/Not Detected"
        )
        
    def calculate_traffic_score(self, handshake_captured: bool) -> RiskFactor:
        """
        Calculate risk based on captured traffic/handshakes.
        Captured handshake = vulnerable to offline cracking.
        
        Args:
            handshake_captured: True if EAPOL handshake captured
            
        Returns:
            RiskFactor
        """
        if handshake_captured:
            return RiskFactor(
                name="traffic",
                weight=self.WEIGHTS["traffic"],
                score=100, # Critical: Handshake captured
                description="Handshake Captured (Vulnerable to Offline Cracking)"
            )
        return RiskFactor(
            name="traffic",
            weight=self.WEIGHTS["traffic"],
            score=0,
            description="No sensitive traffic captured"
        )
    
    def calculate_encryption_score(self, encryption: str) -> RiskFactor:
        """
        Calculate risk score based on encryption type.
        
        Args:
            encryption: Encryption string (e.g., "WPA2-PSK", "Open")
            
        Returns:
            RiskFactor with score
        """
        enc_upper = encryption.upper() if encryption else "UNKNOWN"
        
        # Check specific weak ciphers first
        if "TKIP" in enc_upper and "WPA2" in enc_upper:
            score = self.ENCRYPTION_SCORES["WPA2-TKIP"]
            description = f"Encryption: {encryption} (Weak Cipher)"
            return RiskFactor(name="encryption", weight=self.WEIGHTS["encryption"], score=score, description=description)
            
        # Try exact match first
        for key, score in self.ENCRYPTION_SCORES.items():
            if key.upper() in enc_upper:
                description = f"Encryption: {encryption}"
                if score >= 80:
                    description += " (INSECURE)"
                elif score >= 50:
                    description += " (weak)"
                else:
                    description += " (secure)"
                
                return RiskFactor(
                    name="encryption",
                    weight=self.WEIGHTS["encryption"],
                    score=score,
                    description=description
                )
        
        # Unknown encryption - moderate risk
        return RiskFactor(
            name="encryption",
            weight=self.WEIGHTS["encryption"],
            score=50,
            description=f"Unknown encryption: {encryption}"
        )
    
    def calculate_signal_score(self, rssi: int) -> RiskFactor:
        """
        Calculate risk based on signal strength.
        Strong signal = potentially nearby = higher risk of being targeted.
        
        Args:
            rssi: Signal strength in dBm (negative value)
            
        Returns:
            RiskFactor with score
        """
        # RSSI ranges: -30 (excellent) to -90 (very weak)
        # Stronger signal = potentially more accessible = slightly higher risk
        
        if rssi >= -50:
            score = 60  # Very close, easily accessible
            description = f"RSSI {rssi}dBm (very strong - nearby)"
        elif rssi >= -60:
            score = 45
            description = f"RSSI {rssi}dBm (strong)"
        elif rssi >= -70:
            score = 30
            description = f"RSSI {rssi}dBm (moderate)"
        elif rssi >= -80:
            score = 20
            description = f"RSSI {rssi}dBm (weak)"
        else:
            score = 10
            description = f"RSSI {rssi}dBm (very weak)"
        
        return RiskFactor(
            name="signal_strength",
            weight=self.WEIGHTS["signal_strength"],
            score=score,
            description=description
        )
    
    def calculate_ssid_score(self, ssid: str) -> RiskFactor:
        """
        Analyze SSID for suspicious patterns.
        
        Args:
            ssid: Network SSID
            
        Returns:
            RiskFactor with score
        """
        if not ssid or ssid == "<Hidden>":
            return RiskFactor(
                name="ssid_analysis",
                weight=self.WEIGHTS["ssid_analysis"],
                score=40,
                description="Hidden SSID (potentially suspicious)"
            )
        
        ssid_lower = ssid.lower()
        suspicious_matches = []
        
        for pattern in self.SUSPICIOUS_SSID_PATTERNS:
            if pattern in ssid_lower:
                suspicious_matches.append(pattern)
        
        if suspicious_matches:
            score = min(30 + len(suspicious_matches) * 20, 90)
            return RiskFactor(
                name="ssid_analysis",
                weight=self.WEIGHTS["ssid_analysis"],
                score=score,
                description=f"SSID contains: {', '.join(suspicious_matches)}"
            )
        
        return RiskFactor(
            name="ssid_analysis",
            weight=self.WEIGHTS["ssid_analysis"],
            score=10,
            description=f"SSID: {ssid}"
        )
    
    def calculate_vendor_score(self, vendor: str) -> RiskFactor:
        """
        Assess risk based on vendor.
        
        Args:
            vendor: Vendor name from OUI lookup
            
        Returns:
            RiskFactor with score
        """
        if not vendor:
            vendor = "Unknown"
        
        vendor_lower = vendor.lower()
        
        for suspicious in self.SUSPICIOUS_VENDORS:
            if suspicious in vendor_lower:
                return RiskFactor(
                    name="vendor",
                    weight=self.WEIGHTS["vendor"],
                    score=60,
                    description=f"Vendor: {vendor} (unidentified)"
                )
        
        return RiskFactor(
            name="vendor",
            weight=self.WEIGHTS["vendor"],
            score=10,
            description=f"Vendor: {vendor}"
        )
    
    def calculate_channel_score(self, channel: int) -> RiskFactor:
        """
        Assess risk based on channel.
        
        Args:
            channel: WiFi channel number
            
        Returns:
            RiskFactor with score
        """
        # Standard 2.4GHz channels: 1, 6, 11 (non-overlapping)
        # Unusual channels might indicate testing/attack setup
        
        if channel in [1, 6, 11]:
            score = 10
            description = f"Channel {channel} (standard)"
        elif channel in range(1, 14):
            score = 20
            description = f"Channel {channel} (less common 2.4GHz)"
        elif channel in range(36, 166):
            score = 15
            description = f"Channel {channel} (5GHz)"
        else:
            score = 40
            description = f"Channel {channel} (unusual)"
        
        # Note: Channel is now incorporated into Signal/General context or ignored as primary weight
        # Based on new weights, channel is not explicit, but we can keep method for reference or low weight
        # New weights didn't list Channel. It listed Vendor.
        # I will return a 0-weight factor if not in WEIGHTS, or just skip it.
        # WEIGHTS keys: encryption, wps, traffic, ssid_analysis, signal_strength, vendor.
        # Channel is NOT in new WEIGHTS. So I will deprecate it from calculation.
        return RiskFactor(name="channel", weight=0, score=score, description=description)

    
    def calculate_risk(self, network: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a network.
        
        Args:
            network: Network dictionary with ssid, bssid, encryption, rssi, etc.
            
        Returns:
            Dictionary with risk_score, risk_level, and detailed factors
        """
        factors: List[RiskFactor] = []
        
        # Calculate individual factors
        factors.append(self.calculate_encryption_score(
            network.get("encryption", "Unknown")
        ))
        factors.append(self.calculate_signal_score(
            network.get("rssi", -100)
        ))
        factors.append(self.calculate_ssid_score(
            network.get("ssid", "")
        ))
        factors.append(self.calculate_vendor_score(
            network.get("vendor", "Unknown")
        ))
        
        # New Factors
        factors.append(self.calculate_wps_score(
            network.get("wps", False)
        ))
        factors.append(self.calculate_traffic_score(
            network.get("handshake_captured", False)
        ))
        
        # Calculate weighted score (Using only factors present in WEIGHTS)
        total_score = sum(f.weight * f.score for f in factors if f.weight > 0)
        risk_score = int(round(total_score))
        
        # Determine risk level
        if risk_score >= 90:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 70:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "factors": [
                {
                    "name": f.name,
                    "score": f.score,
                    "weight": f.weight,
                    "weighted_score": round(f.weight * f.score, 1),
                    "description": f.description
                }
                for f in factors
            ],
            "recommendations": self._get_recommendations(risk_level, factors)
        }
    
    def _get_recommendations(
        self, 
        risk_level: RiskLevel, 
        factors: List[RiskFactor]
    ) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []
        
        for factor in factors:
            if factor.name == "encryption" and factor.score >= 80:
                recommendations.append(
                    "⚠️ CRITICAL: This network has no or weak encryption. "
                    "Do NOT connect for sensitive activities."
                )
            elif factor.name == "encryption" and factor.score >= 50:
                recommendations.append(
                    "⚠️ Network uses outdated encryption (WPA/TKIP). "
                    "Consider using VPN if connecting."
                )
            
            if factor.name == "ssid_analysis" and factor.score >= 50:
                recommendations.append(
                    "⚠️ SSID matches suspicious patterns. "
                    "Could be an Evil Twin or honeypot."
                )
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append(
                "🚨 AVOID this network. High probability of attack surface."
            )
        elif risk_level == RiskLevel.HIGH:
            recommendations.append(
                "🔒 Use VPN and avoid sensitive transactions."
            )
        
        return recommendations if recommendations else ["✓ No immediate concerns detected."]


# Convenience function
def calculate_risk_score(network: Dict[str, Any]) -> int:
    """
    Quick risk score calculation.
    
    Args:
        network: Network dictionary
        
    Returns:
        Risk score (0-100)
    """
    scorer = RiskScorer()
    result = scorer.calculate_risk(network)
    return result["risk_score"]


def get_risk_color(score: int) -> str:
    """Get color code for risk score (for GUI display)."""
    if score >= 90:
        return "#FF0000"  # Red - Critical
    elif score >= 70:
        return "#FF6600"  # Orange - High
    elif score >= 40:
        return "#FFCC00"  # Yellow - Medium
    else:
        return "#00CC00"  # Green - Low


if __name__ == "__main__":
    # Test with sample networks
    print("=" * 50)
    print("WiFi Risk Scoring Module Test")
    print("=" * 50)
    
    scorer = RiskScorer()
    
    test_networks = [
        {
            "ssid": "Free_WiFi_Hotspot",
            "bssid": "AA:BB:CC:11:22:33",
            "encryption": "Open",
            "rssi": -45,
            "channel": 6,
            "vendor": "Unknown"
        },
        {
            "ssid": "Home_Network",
            "bssid": "11:22:33:44:55:66",
            "encryption": "WPA2-PSK",
            "rssi": -55,
            "channel": 11,
            "vendor": "Apple"
        },
        {
            "ssid": "Corp_Secure",
            "bssid": "AA:11:22:33:44:55",
            "encryption": "WPA3-SAE",
            "rssi": -70,
            "channel": 36,
            "vendor": "Cisco"
        }
    ]
    
    for net in test_networks:
        result = scorer.calculate_risk(net)
        print(f"\nNetwork: {net['ssid']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Risk Level: {result['risk_level'].upper()}")
        print(f"  Color: {get_risk_color(result['risk_score'])}")
        print("  Factors:")
        for f in result["factors"]:
            print(f"    - {f['name']}: {f['score']} x {f['weight']} = {f['weighted_score']}")
        print("  Recommendations:")
        for rec in result["recommendations"]:
            print(f"    {rec}")
