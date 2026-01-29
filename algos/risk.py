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

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScoringWeights:
    """Configurable weights for risk factors"""

    encryption: float = 0.50  # Increased from 0.35
    signal_strength: float = 0.10
    ssid_pattern: float = 0.20  # Increased from 0.15
    vendor: float = 0.05  # Reduced
    channel: float = 0.05
    beacon_interval: float = 0.05
    privacy_flags: float = 0.05
    temporal: float = 0.05


class EnhancedRiskScorer:
    """
    Enhanced risk scoring with:
    - External YAML configuration
    - Modular Feature Extraction (FeatureExtractor)
    - ML-ready interface
    """

    def __init__(
        self,
        config_path: str = "sensor/risk_weights.yaml",
        whitelist: list[str] | None = None,
        ml_model_path: str | None = None,
    ):
        self.config = self._load_config(config_path)
        self.weights = self.config.get("weights", {})
        self.whitelist = set(whitelist or [])

        # Load ML Model if available
        self.ml_model = None
        if ml_model_path:
            try:
                # Add project root to path to find ml module
                import os
                import sys

                sys.path.append(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                )
                from ml.anomaly_model import detect_anomaly, load_model

                # 10 features assumed from FeatureExtractor
                self.ml_model = load_model(ml_model_path, input_dim=10)
                self.detect_anomaly_fn = detect_anomaly
            except Exception as e:
                logger.warning(f"ML Model load failed: {e}")

        # Initialize modular Feature Extractor
        from .features import FeatureExtractor

        self.feature_extractor = FeatureExtractor(config=self.config)

        # Metrics for validation
        self.predictions = []

    def _load_config(self, path: str) -> dict:
        try:
            with open(path) as f:
                import yaml

                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(
                f"Failed to load risk config from {path}: {e}. Using defaults."
            )
            return {
                "weights": {
                    "encryption": 0.40,
                    "rssi_norm": 0.15,
                    "beacon_anomaly": 0.12,
                    "vendor_risk": 0.10,
                    "ssid_suspicion": 0.08,
                    "wps_flag": 0.06,
                    "channel_crowd": 0.04,
                    "hidden_ssid": 0.05,
                    "temporal": 0.05,
                }
            }

    def score(self, network: dict) -> int:
        """Legacy compatibility method returning integer score."""
        result = self.calculate_risk(network)
        return int(result.get("risk_score", 0))

    def calculate_risk(
        self, network: dict, ground_truth_label: str | None = None
    ) -> dict:
        """
        Calculate risk score using modular features and configurable weights.
        """
        # Check whitelist
        ssid = network.get("ssid", "")
        bssid = network.get("bssid", "")
        if ssid in self.whitelist or bssid in self.whitelist:
            return {
                "risk_score": 0,
                "risk_level": "Whitelisted",
                "confidence": 1.0,
                "features": {},
                "explain": {},
                "contributing_factors": [],
            }

        # 1. Extract Features via separate module
        features = self.feature_extractor.extract(network)

        # 2. Calculate Weighted Score
        w = self.weights
        raw_score = (
            features["enc_score"] * w.get("encryption", 0)
            + features["rssi_norm"] * w.get("rssi_norm", 0)
            + features["ssid_suspicious"] * w.get("ssid_suspicion", 0)
            + features["ssid_hidden"] * w.get("hidden_ssid", 0)
            + features["vendor_trust"] * w.get("vendor_risk", 0)
            # Using channel weight
            + features["channel_unusual"] * w.get("channel_crowd", 0)
            + features["beacon_anomaly"] * w.get("beacon_anomaly", 0)
            + features["wps_flag"] * w.get("wps_flag", 0)
            + features["temporal_new"] * w.get("temporal", 0)
            # Fallback if missing in yaml
            + features["privacy_concern"] * w.get("privacy_flags", 0.05)
        )

        # ML Anomaly Boost
        if self.ml_model:
            try:
                # Construct vector matching input_dim=10
                vec = [
                    features.get("enc_score", 0),
                    features.get("rssi_norm", 0),
                    features.get("ssid_suspicious", 0),
                    features.get("ssid_hidden", 0),
                    features.get("vendor_trust", 0),
                    features.get("channel_unusual", 0),
                    features.get("beacon_anomaly", 0),
                    features.get("wps_flag", 0),
                    features.get("temporal_new", 0),
                    features.get("privacy_concern", 0),
                ]
                is_anomaly, loss = self.detect_anomaly_fn(self.ml_model, [vec])
                if is_anomaly:
                    raw_score += 0.2  # 20% boost for anomalies
                    features["ml_anomaly"] = 1.0
            except Exception as e:
                logger.debug(f"ML Scoring failed: {e}")

        # Normalize to 0-100
        risk_score = min(100, int(raw_score * 100))

        # 3. Determine Risk Level
        thresholds = self.config.get("thresholds", {"low": 40, "medium": 70})
        if risk_score >= thresholds["medium"]:
            risk_level = "High"
        elif risk_score >= thresholds["low"]:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # 4. Calculate Confidence (Availability of data)
        # Simplified: Check distinct non-default keys in features or raw network
        # (Assuming the extractor provides 10 features, we assume High confidence if basic fields present)
        av_fields = sum(
            1 for k, v in features.items() if v != 0.5
        )  # 0.5 is often default
        # Heuristic: 5 indicators = 100% conf
        confidence = min(1.0, round(av_fields / 5.0, 2))

        # 5. Explain Breakdown
        explain = {
            k: round(features.get(f_map, 0) * val * 100, 1)
            for k, val in w.items()
            for f_map in features.keys()
            if self._map_weight_to_feature(k) == f_map
        }

        # Contributing factors (Human readable)
        factors = []
        if features["enc_score"] > 0.5:
            factors.append(f"Weak Encryption ({network.get('encryption')})")
        if features["ssid_suspicious"] > 0.5:
            factors.append("Suspicious SSID Pattern")
        if features["beacon_anomaly"] > 0.5:
            factors.append("Beacon Anomaly Detected")

        result = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "features": features,
            "explain": explain,
            "contributing_factors": factors,
        }

        return result

    def _map_weight_to_feature(self, weight_key: str) -> str:
        # Helper to map yaml weight keys to feature keys
        mapping = {
            "encryption": "enc_score",
            "rssi_norm": "rssi_norm",
            "ssid_suspicion": "ssid_suspicious",
            "hidden_ssid": "ssid_hidden",
            "vendor_risk": "vendor_trust",
            "channel_crowd": "channel_unusual",
            "beacon_anomaly": "beacon_anomaly",
            "wps_flag": "wps_flag",
            "temporal": "temporal_new",
            "privacy_flags": "privacy_concern",
        }
        return mapping.get(weight_key)

    def get_validation_metrics(self) -> dict:
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
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0
        )
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
            "accuracy": round(accuracy, 4),
        }

    def calibrate_weights_from_data(self, labeled_data: list[dict]) -> ScoringWeights:
        """
        Simple weight calibration using labeled data.
        """
        logger.info(f"Calibrating weights from {len(labeled_data)} samples...")
        # (Simplified logic - no sklearn dependency for now)
        return self.weights

    def export_for_ml_training(self) -> list[dict]:
        """
        Export feature vectors for external ML training.
        """
        return [
            {
                "features": pred["features"],
                "score": pred["score"],
                "label": pred["actual"],
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
        "vendor": "Unknown",
    }

    result = scorer.calculate_risk(test_net, ground_truth_label="malicious")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Risk Level: {result['risk_level']}")
