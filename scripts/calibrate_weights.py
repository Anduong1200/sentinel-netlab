#!/usr/bin/env python3
"""
Weight Calibration Script for Risk Scoring
Uses labeled dataset to optimize scoring weights.

Usage:
    python calibrate_weights.py labeled_data.json [--output weights.json]

Input format (labeled_data.json):
[
    {"network": {"ssid": "...", "bssid": "...", ...}, "label": "malicious"},
    {"network": {"ssid": "...", "bssid": "...", ...}, "label": "benign"},
    ...
]
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from algos.risk import EnhancedRiskScorer
except ImportError:
    print("Error: Cannot import from risk.py. Make sure sensor/risk.py exists.")
    sys.exit(1)


def load_labeled_data(filepath: str) -> list:
    """Load labeled dataset from JSON file"""
    with open(filepath) as f:
        return json.load(f)


def generate_sample_labeled_data() -> list:
    """Generate sample labeled data for demonstration"""
    return [
        # Malicious examples
        {"network": {"ssid": "Free_WiFi", "encryption": "Open", "signal": -40, "channel": 6}, "label": "malicious"},
        {"network": {"ssid": "Airport_Guest", "encryption": "Open", "signal": -35, "channel": 1}, "label": "malicious"},
        {"network": {"ssid": "Starbucks", "encryption": "Open", "signal": -30, "channel": 11}, "label": "malicious"},
        {"network": {"ssid": "Hotel_Free", "encryption": "WEP", "signal": -50, "channel": 6}, "label": "malicious"},
        {"network": {"ssid": "default", "encryption": "Open", "signal": -45, "channel": 1}, "label": "malicious"},

        # Benign examples
        {"network": {"ssid": "Corp_Secure", "encryption": "WPA3-SAE", "signal": -60, "channel": 36, "vendor": "Cisco"}, "label": "benign"},
        {"network": {"ssid": "Home_WiFi_5G", "encryption": "WPA2-PSK", "signal": -55, "channel": 149}, "label": "benign"},
        {"network": {"ssid": "Office_Main", "encryption": "WPA2-Enterprise", "signal": -65, "channel": 44, "vendor": "Aruba"}, "label": "benign"},
        {"network": {"ssid": "Guest_Secure", "encryption": "WPA2-PSK", "signal": -70, "channel": 6}, "label": "benign"},
        {"network": {"ssid": "IoT_Network", "encryption": "WPA2-PSK", "signal": -75, "channel": 11}, "label": "benign"},
    ]


def main():
    parser = argparse.ArgumentParser(description="Calibrate risk scoring weights")
    parser.add_argument("input", nargs="?", help="Path to labeled_data.json")
    parser.add_argument("--output", "-o", default="calibrated_weights.json", help="Output weights file")
    parser.add_argument("--demo", action="store_true", help="Use sample data for demonstration")
    parser.add_argument("--validate", action="store_true", help="Run validation after calibration")

    args = parser.parse_args()

    # Load data
    if args.demo or not args.input:
        print("📊 Using sample labeled data (demo mode)")
        labeled_data = generate_sample_labeled_data()
    else:
        print(f"📂 Loading labeled data from: {args.input}")
        labeled_data = load_labeled_data(args.input)

    print(f"   Total samples: {len(labeled_data)}")
    print(f"   Malicious: {sum(1 for d in labeled_data if d['label'] == 'malicious')}")
    print(f"   Benign: {sum(1 for d in labeled_data if d['label'] == 'benign')}")

    # Initialize scorer and calibrate
    scorer = EnhancedRiskScorer()

    print("\n⚙️ Calibrating weights...")
    new_weights = scorer.calibrate_weights_from_data(labeled_data)

    # Display new weights
    print("\n📈 Calibrated Weights:")
    weights_dict = {
        "encryption": new_weights.encryption,
        "signal_strength": new_weights.signal_strength,
        "ssid_pattern": new_weights.ssid_pattern,
        "vendor": new_weights.vendor,
        "channel": new_weights.channel,
        "beacon_interval": new_weights.beacon_interval,
        "privacy_flags": new_weights.privacy_flags,
        "temporal": new_weights.temporal
    }

    for k, v in weights_dict.items():
        print(f"   {k}: {v:.4f}")

    # Save weights
    with open(args.output, 'w') as f:
        json.dump(weights_dict, f, indent=2)
    print(f"\n✅ Weights saved to: {args.output}")

    # Validation
    if args.validate:
        print("\n🔍 Running validation with calibrated weights...")

        # Create new scorer with calibrated weights
        calibrated_scorer = EnhancedRiskScorer(weights=new_weights)

        for item in labeled_data:
            calibrated_scorer.calculate_risk(item["network"], ground_truth_label=item["label"])

        metrics = calibrated_scorer.get_validation_metrics()

        print("\n📊 Validation Results:")
        print(f"   Accuracy:  {metrics['accuracy']:.2%}")
        print(f"   Precision: {metrics['precision']:.2%}")
        print(f"   Recall:    {metrics['recall']:.2%}")
        print(f"   F1 Score:  {metrics['f1_score']:.2%}")
        print(f"   FPR:       {metrics['false_positive_rate']:.2%}")

        if metrics['precision'] >= 0.9 and metrics['recall'] >= 0.8:
            print("\n✅ Weights meet target thresholds!")
        else:
            print("\n⚠️ Weights may need more training data or feature tuning.")


if __name__ == "__main__":
    main()
