#!/usr/bin/env python3
"""
Sentinel NetLab - Detection Tuning Toolkit
Optimizes risk weights using grid search against a labeled dataset.
"""

import argparse
import json
import logging

# Add parent dir to path
import sys
from pathlib import Path

import numpy as np
import yaml

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from algos.risk import RiskScorer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_dataset(path: str) -> list[dict]:
    """Load labeled dataset (JSON list of network records with 'label' field)"""
    with open(path) as f:
        return json.load(f)

def evaluate(scorer: RiskScorer, dataset: list[dict], threshold: int = 50) -> dict[str, float]:
    """Calculate metrics for current weights"""
    tp = fp = tn = fn = 0

    for record in dataset:
        true_label = record.get('label', 'benign') # benign or malicious
        score_result = scorer.calculate_risk(record)
        score = score_result['score']

        predicted_malicious = score >= threshold
        is_malicious = true_label == 'malicious'

        if is_malicious and predicted_malicious:
            tp += 1
        elif not is_malicious and predicted_malicious:
            fp += 1
        elif not is_malicious and not predicted_malicious:
            tn += 1
        elif is_malicious and not predicted_malicious:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        'f1': f1,
        'precision': precision,
        'recall': recall,
        'accuracy': (tp + tn) / len(dataset)
    }

def optimize(dataset_path: str, config_path: str):
    """Run grid search optimization"""
    logger.info(f"Loading dataset from {dataset_path}")
    dataset = load_dataset(dataset_path)

    # Define search space (simplified)
    # Weights must sum to ~1.0
    weight_keys = ['encryption', 'rssi_norm', 'vendor_risk', 'ssid_suspicion', 'wps_flag']

    best_f1 = -1.0
    best_weights = {}

    logger.info("Starting optimization...")

    # Very simple random search for demonstration
    # Real implementation would use scikit-learn or more complex grid
    num_trials = 100

    for _i in range(num_trials):
        # Generate random weights summing to 1
        raw_weights = np.random.dirichlet(np.ones(len(weight_keys)), size=1)[0]
        # Round to 2 decimals
        weights = {k: round(float(v), 2) for k, v in zip(weight_keys, raw_weights)}

        # Setup scorer
        # We Mock the config loader to inject our weights
        scorer = RiskScorer(config_path)
        scorer.weights = weights # Override

        metrics = evaluate(scorer, dataset)

        if metrics['f1'] > best_f1:
            best_f1 = metrics['f1']
            best_weights = weights
            logger.info(f"New best F1: {best_f1:.3f} with {weights}")

    print("\n" + "="*50)
    print("Optimization Result")
    print(f"Best F1 Score: {best_f1:.3f}")
    print("Recommended Weights:")
    print(yaml.dump(best_weights))
    print("="*50)

def main():
    parser = argparse.ArgumentParser(description='Risk Weight Tuner')
    parser.add_argument('--dataset', required=True, help='Path to labeled JSON dataset')
    parser.add_argument('--config', default='sensor/risk_weights.yaml', help='Base config path')
    args = parser.parse_args()

    optimize(args.dataset, args.config)

if __name__ == "__main__":
    main()
