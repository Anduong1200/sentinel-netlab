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

sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock storage or import real if available
# For this tool, we assume input is the raw JSON logs or DB
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def export_to_csv(input_file: str, output_file: str):
    """Convert JSON telemetry log to CSV features"""

    logger.info(f"Reading {input_file}...")
    with open(input_file) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get('items', [])

    if not items:
        logger.warning("No data found")
        return

    # Define feature columns
    fieldnames = [
        'timestamp', 'sensor_id',
        'rssi_dbm', 'channel',
        'encryption_opent', 'encryption_wep', 'encryption_wpa2', 'encryption_wpa3',
        'is_hidden', 'wps_enabled',
        'vendor_oui',
        'label' # Manual label if present
    ]

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        count = 0
        for item in items:
            # Flatten/Normalize features
            row = {
                'timestamp': item.get('timestamp_utc'),
                'sensor_id': item.get('sensor_id'),
                'rssi_dbm': item.get('rssi_dbm'),
                'channel': item.get('channel'),
                'vendor_oui': item.get('vendor_oui'),
                'is_hidden': 1 if not item.get('ssid') else 0,
                'wps_enabled': 1 if item.get('capabilities', {}).get('wps') else 0,
                'label': item.get('label', 'unknown')
            }

            # One-hot encoding for encryption (simplified)
            # In real code, parse 'security' string
            # Here we assume capability flags or similar
            caps = item.get('capabilities', {})
            row['encryption_opent'] = 1 if not caps.get('privacy') else 0
            row['encryption_wep'] = 0 # Need better logic
            row['encryption_wpa2'] = 1 if caps.get('privacy') and not caps.get('pmf') else 0
            row['encryption_wpa3'] = 1 if caps.get('pmf') else 0

            writer.writerow(row)
            count += 1

    logger.info(f"Exported {count} records to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Dataset Exporter')
    parser.add_argument('--input', required=True, help='Input JSON telemetry file')
    parser.add_argument('--output', required=True, help='Output CSV file')
    args = parser.parse_args()

    export_to_csv(args.input, args.output)

if __name__ == "__main__":
    main()
