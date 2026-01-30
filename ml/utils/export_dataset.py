#!/usr/bin/env python3
"""
Sentinel NetLab - Dataset Exporter
Export network records and features to CSV for ML training.
"""

import argparse
import csv
import json
import logging

# Add parent dir to path
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.features import extract_features, get_feature_names

# Mock storage or import real if available
# For this tool, we assume input is the raw JSON logs or DB
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def export_to_csv(input_file: str, output_file: str):
    """Convert JSON telemetry log to CSV features"""

    logger.info(f"Reading {input_file}...")
    with open(input_file) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("items", [])

    if not items:
        logger.warning("No data found")
        return

    # Define feature columns
    fieldnames = ["timestamp", "sensor_id", "label"] + get_feature_names()

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        count = 0
        for item in items:
            # Flatten/Normalize features via shared logic
            feats = extract_features(item)

            row = {
                "timestamp": item.get("timestamp_utc"),
                "sensor_id": item.get("sensor_id"),
                "label": item.get("label", "unknown"),
            }
            row.update(feats)

            writer.writerow(row)
            count += 1

    logger.info(f"Exported {count} records to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Dataset Exporter")
    parser.add_argument("--input", required=True, help="Input JSON telemetry file")
    parser.add_argument("--output", required=True, help="Output CSV file")
    args = parser.parse_args()

    export_to_csv(args.input, args.output)


if __name__ == "__main__":
    main()
