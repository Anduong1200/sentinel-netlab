# Data Directory

This directory is intended for:
- Synthetic PCAP files for testing.
- Labeled datasets for ML training.
- Exported JSON sessions from Wardriving.

## Quick Start
Generate synthetic data using `tools/export_dataset.py` (if available) or use Scapy to generate test PCAPs.

## Structure
- `datasets/`: CSV/JSON datasets.
- `pcap_annotated/`: PCAPs with ground truth labels.
