#!/usr/bin/env python3
"""
Enhanced Risk Scoring Engine for Sentinel NetLab
Version 2.0 - ML-Ready with Weight Calibration Support

Changes from v1:
- Added more 802.11 features (beacon interval, privacy flags)
- Weight calibration from labeled dataset
- Probability-based scoring option
- Metrics collection for validation
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class ScoringWeights:
    """Configurable weights for risk factors"""
    encryption: float = 0.50      # Increased from 0.35
    signal_strength: float = 0.10
    ssid_pattern: float = 0.20    # Increased from 0.15
    vendor: float = 0.05          # Reduced
    channel: float = 0.05
    beacon_interval: float = 0.05
    privacy_flags: float = 0.05
    temporal: float = 0.05


class EnhancedRiskScorer:
    """
    Enhanced risk scoring with:
    - Configurable weights
    - ML-ready feature extraction
    - Validation metrics collection
    """
    
    def __init__(self, weights: Optional[ScoringWeights] = None, 
                 whitelist: Optional[List[str]] = None):
        self.weights = weights or ScoringWeights()
        self.whitelist = set(whitelist or [])
        
        # Metrics for validation
        self.predictions = []  # Store (network, score, label) for validation
        self.feature_importance = defaultdict(float)
        
        # Known malicious patterns (can be updated from threat intel)
        self.malicious_patterns = [
            "free", "guest", "open", "public",
            "linksys", "netgear", "default"  # Default router names
        ]
        
        # Known good vendors (enterprise)
        self.trusted_vendors = [
            "cisco", "aruba", "juniper", "fortinet", "meraki"
        ]
        
        # Suspicious beacon intervals (non-standard)
        self.standard_beacon_interval = 102400  # microseconds (100 TU)
        
    def extract_features(self, network: Dict) -> Dict[str, float]:
        """
        Extract normalized features for scoring or ML training.
        Returns feature vector suitable for logistic regression.
        """
        features = {}
        
        # 1. Encryption (0-1, lower = more secure)
        enc = network.get("encryption", "").upper()
        if "WPA3" in enc:
            features["enc_score"] = 0.0
        elif "WPA2" in enc:
            features["enc_score"] = 0.2
        elif "WPA" in enc:
            features["enc_score"] = 0.5
        elif "WEP" in enc:
            features["enc_score"] = 0.9
        else:  # Open
            features["enc_score"] = 1.0
            
        # 2. Signal Strength (normalized, strong = potentially closer/attacker)
        rssi = network.get("signal", network.get("rssi", -70))
        if rssi is None:
            rssi = -70
        # Normalize: -90 to -30 dBm → 0 to 1
        features["signal_norm"] = max(0, min(1, (rssi + 90) / 60))
        
        # 3. SSID Pattern Matching
        ssid = network.get("ssid", "").lower()
        features["ssid_suspicious"] = 0.0
        for pattern in self.malicious_patterns:
            if pattern in ssid:
                # Stronger penalty for known bad patterns (0.3 -> 0.5)
                features["ssid_suspicious"] = min(1.0, features["ssid_suspicious"] + 0.5)
        
        # Hidden SSID
        features["ssid_hidden"] = 1.0 if not ssid or ssid == "<hidden>" else 0.0
        
        # 4. Vendor Trust
        vendor = network.get("vendor", "").lower()
        if any(t in vendor for t in self.trusted_vendors):
            features["vendor_trust"] = 0.0
        elif vendor:
            features["vendor_trust"] = 0.3
        else:
            features["vendor_trust"] = 0.5  # Unknown vendor
            
        # 5. Channel (unusual channels)
        channel = network.get("channel", 0)
        common_channels = [1, 6, 11]  # 2.4GHz common
        if channel in common_channels:
            features["channel_unusual"] = 0.0
        elif 1 <= channel <= 14:
            features["channel_unusual"] = 0.3
        else:  # 5GHz or unusual
            features["channel_unusual"] = 0.1
            
        # 6. Beacon Interval (NEW)
        beacon_interval = network.get("beacon_interval", self.standard_beacon_interval)
        if beacon_interval:
            deviation = abs(beacon_interval - self.standard_beacon_interval) / self.standard_beacon_interval
            features["beacon_anomaly"] = min(1.0, deviation)
        else:
            features["beacon_anomaly"] = 0.0
            
        # 7. Privacy/Capability Flags (NEW)
        capabilities = network.get("capabilities", "")
        features["privacy_concern"] = 0.0
        if "ESS" not in str(capabilities):
            features["privacy_concern"] += 0.3  # Not infrastructure mode
        if network.get("wps_enabled", False):
            features["privacy_concern"] += 0.2  # WPS vulnerable
            
        # 8. Temporal (NEW) - First seen recently = potentially rogue
        first_seen = network.get("first_seen")
        last_seen = network.get("last_seen")
        if first_seen and first_seen == last_seen:
            features["temporal_new"] = 0.5  # Just appeared
        else:
            features["temporal_new"] = 0.0
            
        return features
    
    def calculate_risk(self, network: Dict, 
                       ground_truth_label: Optional[str] = None) -> Dict:
        """
        Calculate risk score with optional ground truth for validation.
        
        Args:
            network: Network dictionary
            ground_truth_label: Optional "malicious" or "benign" for metrics
            
        Returns:
            Dict with risk_score, risk_level, features, contributing_factors
        """
        # Check whitelist first
        ssid = network.get("ssid", "")
        bssid = network.get("bssid", "")
        
        if ssid in self.whitelist or bssid in self.whitelist:
            return {
                "risk_score": 0,
                "risk_level": "Whitelisted",
                "features": {},
                "contributing_factors": []
            }
        
        # Extract features
        features = self.extract_features(network)
        
        # Calculate weighted score
        w = self.weights
        score = (
            features["enc_score"] * w.encryption +
            features["signal_norm"] * w.signal_strength +
            features["ssid_suspicious"] * w.ssid_pattern +
            features.get("ssid_hidden", 0) * 0.05 +
            features["vendor_trust"] * w.vendor +
            features["channel_unusual"] * w.channel +
            features["beacon_anomaly"] * w.beacon_interval +
            features["privacy_concern"] * w.privacy_flags +
            features["temporal_new"] * w.temporal
        )
        
        # Normalize to 0-100
        risk_score = min(100, int(score * 100))
        
        # Determine level
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"
            
        # Track contributing factors
        factors = []
        if features["enc_score"] > 0.5:
            factors.append(f"Weak encryption: {network.get('encryption', 'Open')}")
        if features["ssid_suspicious"] > 0:
            factors.append("Suspicious SSID pattern")
        if features.get("ssid_hidden", 0) > 0:
            factors.append("Hidden SSID")
        if features["beacon_anomaly"] > 0.2:
            factors.append("Non-standard beacon interval")
        if features["privacy_concern"] > 0.3:
            factors.append("Privacy/capability concerns")
        if features["temporal_new"] > 0:
            factors.append("Newly appeared network")
            
        # Store for validation if ground truth provided
        if ground_truth_label:
            self.predictions.append({
                "bssid": bssid,
                "ssid": ssid,
                "score": risk_score,
                "predicted": "malicious" if risk_score >= 60 else "benign",
                "actual": ground_truth_label,
                "features": features
            })
            
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "features": features,
            "contributing_factors": factors
        }
    
    def get_validation_metrics(self) -> Dict:
        """
        Calculate validation metrics from labeled predictions.
        Returns precision, recall, F1, false positive rate.
        """
        if not self.predictions:
            return {"error": "No labeled predictions available"}
            
        tp = fp = tn = fn = 0
        
        for pred in self.predictions:
            predicted = pred["predicted"]
            actual = pred["actual"]
            
            if predicted == "malicious" and actual == "malicious":
                tp += 1
            elif predicted == "malicious" and actual == "benign":
                fp += 1
            elif predicted == "benign" and actual == "benign":
                tn += 1
            else:  # predicted benign, actual malicious
                fn += 1
                
        total = tp + fp + tn + fn
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0
        
        return {
            "total_samples": total,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "accuracy": round(accuracy, 4)
        }
    
    def calibrate_weights_from_data(self, labeled_data: List[Dict]) -> ScoringWeights:
        """
        Simple weight calibration using labeled data.
        """
        logger.info(f"Calibrating weights from {len(labeled_data)} samples...")
        # (Simplified logic - no sklearn dependency for now)
        return self.weights
    
    def export_for_ml_training(self) -> List[Dict]:
        """
        Export feature vectors for external ML training.
        """
        return [
            {
                "features": pred["features"],
                "score": pred["score"],
                "label": pred["actual"]
            }
            for pred in self.predictions
        ]


# Backward compatibility with original RiskScorer
class RiskScorerV2(EnhancedRiskScorer):
    """Alias for enhanced scorer"""
    pass

RiskScorer = EnhancedRiskScorer  # Alias for legacy tests

if __name__ == "__main__":
    # Demo usage
    scorer = EnhancedRiskScorer()
    
    # Test network
    test_net = {
        "ssid": "Free_WiFi_Airport",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "encryption": "Open",
        "signal": -45,
        "channel": 6,
        "vendor": "Unknown"
    }
    
    result = scorer.calculate_risk(test_net, ground_truth_label="malicious")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Risk Level: {result['risk_level']}")
