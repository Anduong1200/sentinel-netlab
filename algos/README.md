# Algorithms Module

This module contains the core detection and analysis algorithms used by Sentinel NetLab.
It provides modular, reusable components for the Sensor and Controller.

## Detectors

| Module | Description | MITRE ATT&CK |
|--------|-------------|---------------|
| `evil_twin.py` | Advanced Evil Twin detection using weighted risk scoring (RSSI, Vendor, Security, Jitter) | T1557.002 |
| `dos.py` | Deauthentication Flood detection using sliding window analysis | T1499.001 |
| `disassoc_detector.py` | Disassociation Flood detection with multi-client severity escalation | T1499.001 |
| `beacon_flood_detector.py` | Beacon Flood / Fake AP detection via unique SSID and BSSID diversity | T1498.001 |
| `krack_detector.py` | KRACK (Key Reinstallation) detection — EAPOL M3 replay monitoring | T1557.002 |
| `pmkid_detector.py` | PMKID Harvesting detection — dual-layer Auth flood + orphaned EAPOL M1 | T1110.002 |
| `karma_detector.py` | Karma/WiFi Pineapple detection — rogue APs responding to multiple SSIDs | T1583.008 |
| `jamming_detector.py` | RF Jamming detection — monitors packet loss, RTS/CTS floods, anomalous RSSI | T1465 |
| `wardrive_detector.py` | Wardriving detection — identifies mobile scanning patterns | T1595.002 |
| `wep_iv_detector.py` | WEP IV collision and packet injection detection | T1600.001 |
| `exploit_chain_analyzer.py` | Multi-stage attack correlation — links related detections into attack chains | TA0001 |

## Analysis & Scoring

| Module | Description |
|--------|-------------|
| `risk.py` | Configurable Risk Scoring Engine (encapsulates `features.py`) |
| `features.py` | Feature extraction logic for ML and risk scoring |
| `baseline.py` | Time-series behavioral baselining (72-hour learning window) |
| `detection.py` | Utilities: Levenshtein distance, Bloom Filter |

## Usage

```python
from algos import (
    DeauthFloodDetector,
    DisassocFloodDetector,
    BeaconFloodDetector,
    KRACKDetector,
    PMKIDAttackDetector,
    KarmaDetector,
)

# Initialize
dos = DeauthFloodDetector()
disassoc = DisassocFloodDetector()
beacon = BeaconFloodDetector()
krack = KRACKDetector()
pmkid = PMKIDAttackDetector()
karma = KarmaDetector()

# Process frames from sensor pipeline
dos_alert = dos.record_deauth(bssid, client_mac)
disassoc_alert = disassoc.ingest(telemetry_data)
beacon_alert = beacon.ingest(telemetry_data)
krack_alert = krack.ingest(telemetry_data)
pmkid_alert = pmkid.ingest(telemetry_data)
karma_alert = karma.ingest(telemetry_data)
```
