# Algorithms Module

This module contains the core detection and analysis algorithms used by Sentinel NetLab.
It provides modular, reusable components for the Sensor and Controller.

## Detectors

| Module | Description |
|--------|-------------|
| `evil_twin.py` | Advanced Evil Twin detection using weighted risk scoring (RSSI, Vendor, Security, Jitter) |
| `dos.py` | Deauthentication Flood detection using sliding window analysis |
| `karma_detector.py` | Karma/WiFi Pineapple detection — rogue APs responding to multiple SSIDs |
| `jamming_detector.py` | RF Jamming detection — monitors packet loss, RTS/CTS floods, anomalous RSSI |
| `wardrive_detector.py` | Wardriving detection — identifies mobile scanning patterns |
| `wep_iv_detector.py` | WEP IV collision and packet injection detection |
| `exploit_chain_analyzer.py` | Multi-stage attack correlation — links related detections into attack chains |

## Analysis & Scoring

| Module | Description |
|--------|-------------|
| `risk.py` | Configurable Risk Scoring Engine (encapsulates `features.py`) |
| `features.py` | Feature extraction logic for ML and risk scoring |
| `baseline.py` | Time-series behavioral baselining (72-hour learning window) |
| `detection.py` | Utilities: Levenshtein distance, Bloom Filter |

## Usage

```python
from algos.evil_twin import AdvancedEvilTwinDetector
from algos.dos import DeauthFloodDetector
from algos.karma_detector import KarmaDetector

# Initialize
et_detector = AdvancedEvilTwinDetector()
dos_detector = DeauthFloodDetector()
karma_detector = KarmaDetector()

# Process
alerts = et_detector.ingest(telemetry_data)
flood_alert = dos_detector.record_deauth(bssid, client_mac)
```
