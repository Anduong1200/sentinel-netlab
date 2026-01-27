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
        "encryption": 0.45,      # Most important
        "signal_strength": 0.20, # Proximity indicator
        "ssid_analysis": 0.15,   # Hidden/suspicious names
        "vendor": 0.10,          # Known vulnerable vendors
        "channel": 0.10,         # Channel congestion/unusual
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
        "WPA2": 25,
        "WPA2-PSK": 20,
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
    
    def calculate_encryption_score(self, encryption: str) -> RiskFactor:
        """
        Calculate risk score based on encryption type.
        
        Args:
            encryption: Encryption string (e.g., "WPA2-PSK", "Open")
            
        Returns:
            RiskFactor with score
        """
        enc_upper = encryption.upper() if encryption else "UNKNOWN"
        
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
        
        return RiskFactor(
            name="channel",
            weight=self.WEIGHTS["channel"],
            score=score,
            description=description
        )
    
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
        factors.append(self.calculate_channel_score(
            network.get("channel", 0)
        ))
        
        # Calculate weighted score
        total_score = sum(f.weight * f.score for f in factors)
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
