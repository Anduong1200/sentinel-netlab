# Algorithms Module

This module contains the core detection and analysis algorithms used by Sentinel NetLab.
It has been consolidated to provide modular, reusable components for the Sensor and Controller.

## Components

- **`evil_twin.py`**: Advanced Evil Twin detection using weighted risk scoring (RSSI, Vendor, Security, Jitter).
- **`dos.py`**: Deauthentication Flood detection using sliding window analysis.
- **`baseline.py`**: Time-series behavioral baselining (72-hour learning window).
- **`risk.py`**: Configurable Risk Scoring Engine (encapsulates `features.py`).
- **`features.py`**: Feature extraction logic for machine learning and risk scoring.
- **`detection.py`**: Legacy/Helper utilities (Levenshtein, BloomFilter).

## Usage

```python
from algos.evil_twin import AdvancedEvilTwinDetector
from algos.dos import DeauthFloodDetector

# Initialize
et_detector = AdvancedEvilTwinDetector()
dos_detector = DeauthFloodDetector()

# Process
alerts = et_detector.ingest(telemetry_data)
flood_alert = dos_detector.record_deauth(bssid, client_mac)
```

## Benchmarking
Run benchmarks using `pytest algos/benchmarks/`.
