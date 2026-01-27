#!/usr/bin/env python3
"""
Advanced Detection Algorithms
Implements Levenshtein distance for Evil Twin, Bloom Filter for MAC blacklist.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings.
    Used for fuzzy SSID matching to detect Evil Twins.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        Edit distance (number of insertions/deletions/substitutions)
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost is 0 if characters match, 1 otherwise
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def ssid_similarity(ssid1: str, ssid2: str) -> float:
    """
    Calculate similarity ratio between two SSIDs.
    
    Args:
        ssid1: First SSID
        ssid2: Second SSID
        
    Returns:
        Similarity ratio (0.0 to 1.0, 1.0 = identical)
    """
    if not ssid1 or not ssid2:
        return 0.0
    
    distance = levenshtein_distance(ssid1.lower(), ssid2.lower())
    max_len = max(len(ssid1), len(ssid2))
    
    if max_len == 0:
        return 1.0
    
    return 1.0 - (distance / max_len)


class BloomFilter:
    """
    Probabilistic data structure for fast MAC address blacklist lookup.
    Memory efficient for large blacklists with small false positive rate.
    """
    
    def __init__(self, expected_items: int = 10000, false_positive_rate: float = 0.01):
        """
        Initialize Bloom Filter.
        
        Args:
            expected_items: Expected number of items
            false_positive_rate: Acceptable false positive rate
        """
        # Calculate optimal size and hash count
        import math
        self.size = int(-expected_items * math.log(false_positive_rate) / (math.log(2) ** 2))
        self.hash_count = int((self.size / expected_items) * math.log(2))
        self.bit_array = [False] * self.size
        self.item_count = 0
        
    def _hashes(self, item: str) -> List[int]:
        """Generate hash values for an item."""
        hashes = []
        for i in range(self.hash_count):
            h = hashlib.sha256(f"{item}{i}".encode()).hexdigest()
            hashes.append(int(h, 16) % self.size)
        return hashes
    
    def add(self, item: str):
        """Add item to filter."""
        for h in self._hashes(item):
            self.bit_array[h] = True
        self.item_count += 1
    
    def contains(self, item: str) -> bool:
        """Check if item might be in filter (may have false positives)."""
        return all(self.bit_array[h] for h in self._hashes(item))
    
    def __contains__(self, item: str) -> bool:
        return self.contains(item)


class EvilTwinDetector:
    """
    Detects Evil Twin attacks using fuzzy SSID matching and BSSID analysis.
    """
    
    def __init__(self, similarity_threshold: float = 0.8):
        """
        Initialize detector.
        
        Args:
            similarity_threshold: Minimum similarity to flag as potential Evil Twin
        """
        self.similarity_threshold = similarity_threshold
        self.known_networks: Dict[str, Dict[str, Any]] = {}  # SSID -> {bssid, encryption, vendor}
        self.alerts: List[Dict[str, Any]] = []
        
    def register_network(self, ssid: str, bssid: str, encryption: str = "", vendor: str = ""):
        """Register a known legitimate network."""
        self.known_networks[ssid.lower()] = {
            "ssid": ssid,
            "bssid": bssid.upper(),
            "encryption": encryption,
            "vendor": vendor,
            "first_seen": datetime.now().isoformat()
        }
    
    def check_network(self, ssid: str, bssid: str, encryption: str = "", vendor: str = "") -> Optional[Dict[str, Any]]:
        """
        Check a network for potential Evil Twin.
        
        Returns:
            Alert dict if suspicious, None otherwise
        """
        if not ssid or ssid == "<Hidden>":
            return None
            
        ssid_lower = ssid.lower()
        bssid_upper = bssid.upper()
        
        # Check 1: Exact SSID match but different BSSID
        if ssid_lower in self.known_networks:
            known = self.known_networks[ssid_lower]
            if known["bssid"] != bssid_upper:
                alert = {
                    "type": "evil_twin_exact",
                    "severity": "CRITICAL",
                    "ssid": ssid,
                    "expected_bssid": known["bssid"],
                    "detected_bssid": bssid_upper,
                    "expected_encryption": known.get("encryption"),
                    "detected_encryption": encryption,
                    "timestamp": datetime.now().isoformat(),
                    "message": f"Evil Twin detected: '{ssid}' with unexpected BSSID"
                }
                self.alerts.append(alert)
                return alert
        
        # Check 2: Fuzzy SSID match (typosquatting)
        for known_ssid, known_info in self.known_networks.items():
            similarity = ssid_similarity(ssid_lower, known_ssid)
            
            if similarity >= self.similarity_threshold and similarity < 1.0:
                # Similar but not exact match
                if known_info["bssid"] != bssid_upper:
                    distance = levenshtein_distance(ssid_lower, known_ssid)
                    alert = {
                        "type": "evil_twin_fuzzy",
                        "severity": "HIGH",
                        "ssid": ssid,
                        "similar_to": known_info["ssid"],
                        "similarity": round(similarity, 2),
                        "edit_distance": distance,
                        "detected_bssid": bssid_upper,
                        "expected_bssid": known_info["bssid"],
                        "timestamp": datetime.now().isoformat(),
                        "message": f"Potential Evil Twin: '{ssid}' similar to '{known_info['ssid']}' ({int(similarity*100)}% match)"
                    }
                    self.alerts.append(alert)
                    return alert
        
        return None
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        return self.alerts[-limit:]


class DeauthFloodDetector:
    """
    Detects Deauthentication flood attacks using time-window analysis.
    """
    
    def __init__(self, threshold: int = 10, window_seconds: float = 1.0):
        """
        Initialize detector.
        
        Args:
            threshold: Number of deauths in window to trigger alert
            window_seconds: Time window in seconds
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.deauth_events: List[float] = []  # Timestamps
        self.alerts: List[Dict[str, Any]] = []
        self.last_alert_time = 0
        
    def add_deauth(self, timestamp: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Record a deauth event and check for flood.
        
        Returns:
            Alert if flood detected, None otherwise
        """
        now = timestamp or time.time()
        self.deauth_events.append(now)
        
        # Clean old events
        cutoff = now - self.window_seconds * 2
        self.deauth_events = [t for t in self.deauth_events if t > cutoff]
        
        # Count events in current window
        window_start = now - self.window_seconds
        count = sum(1 for t in self.deauth_events if t >= window_start)
        
        # Check threshold
        if count >= self.threshold:
            # Avoid alert spam (min 5s between alerts)
            if now - self.last_alert_time < 5.0:
                return None
                
            self.last_alert_time = now
            alert = {
                "type": "deauth_flood",
                "severity": "CRITICAL",
                "count": count,
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "timestamp": datetime.fromtimestamp(now).isoformat(),
                "message": f"Deauth flood: {count} frames in {self.window_seconds}s (threshold: {self.threshold})"
            }
            self.alerts.append(alert)
            return alert
        
        return None


# Singleton instances
_mac_blacklist = BloomFilter(expected_items=100000)
_evil_twin_detector = EvilTwinDetector()
_deauth_detector = DeauthFloodDetector()


def get_mac_blacklist() -> BloomFilter:
    return _mac_blacklist

def get_evil_twin_detector() -> EvilTwinDetector:
    return _evil_twin_detector

def get_deauth_detector() -> DeauthFloodDetector:
    return _deauth_detector


# Import time for timestamp
import time


if __name__ == "__main__":
    print("=" * 50)
    print("Detection Algorithms Test")
    print("=" * 50)
    
    # Test Levenshtein distance
    print("\n[Levenshtein Distance Tests]")
    test_cases = [
        ("CoffeeHouse", "Coffee_House"),
        ("CoffeeHouse", "CoffeHouse"),
        ("FreeWifi", "Free_Wifi"),
        ("CompanyNet", "CompanyNet"),
        ("Airport_Wifi", "Airport_WiFi"),
    ]
    for s1, s2 in test_cases:
        dist = levenshtein_distance(s1, s2)
        sim = ssid_similarity(s1, s2)
        print(f"  '{s1}' vs '{s2}': distance={dist}, similarity={sim:.2f}")
    
    # Test Evil Twin Detector
    print("\n[Evil Twin Detector Tests]")
    detector = EvilTwinDetector(similarity_threshold=0.7)
    
    # Register known networks
    detector.register_network("CoffeeHouse", "AA:BB:CC:DD:EE:FF", "WPA2-PSK")
    detector.register_network("CompanyNet", "11:22:33:44:55:66", "WPA2-Enterprise")
    
    # Check suspicious networks
    networks_to_check = [
        ("CoffeeHouse", "XX:XX:XX:XX:XX:XX"),  # Exact match, wrong BSSID
        ("Coffee_House", "YY:YY:YY:YY:YY:YY"),  # Typosquatting
        ("CofeeHouse", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"),  # Typo
        ("RandomNet", "00:00:00:00:00:00"),  # Unknown
    ]
    
    for ssid, bssid in networks_to_check:
        alert = detector.check_network(ssid, bssid)
        if alert:
            print(f"  ⚠️  {alert['type']}: {alert['message']}")
        else:
            print(f"  ✅ '{ssid}' is clean")
    
    # Test Bloom Filter
    print("\n[Bloom Filter Tests]")
    bf = BloomFilter(expected_items=1000)
    bf.add("AA:BB:CC:DD:EE:FF")
    bf.add("11:22:33:44:55:66")
    
    print(f"  AA:BB:CC:DD:EE:FF in filter: {bf.contains('AA:BB:CC:DD:EE:FF')}")
    print(f"  XX:XX:XX:XX:XX:XX in filter: {bf.contains('XX:XX:XX:XX:XX:XX')}")
    
    # Test Deauth Flood Detector
    print("\n[Deauth Flood Detector Tests]")
    deauth = DeauthFloodDetector(threshold=5, window_seconds=1.0)
    
    base_time = time.time()
    for i in range(15):
        alert = deauth.add_deauth(base_time + i * 0.1)  # 10 deauths/second
        if alert:
            print(f"  🔴 Alert: {alert['message']}")
    
    print("\nAll tests completed!")
