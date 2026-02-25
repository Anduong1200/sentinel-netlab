# Detection Philosophy

Sentinel NetLab utilizes a **hybrid detection strategy** combining signature-based rules for known threats with behavioral anomaly detection for novel attacks.

## 1. Active Detectors

### Signature / Rule-Based

| Detector | Module | Description |
|----------|--------|-------------|
| **Evil Twin** | `algos.evil_twin` | Weighted risk scoring (RSSI, vendor, security, jitter) to detect rogue APs |
| **Deauth Flood** | `algos.dos` | Sliding-window deauthentication frame rate analysis |
| **Disassoc Flood** | `algos.disassoc_detector` | Sliding-window disassociation frame rate analysis with multi-client severity |
| **Beacon Flood** | `algos.beacon_flood_detector` | Fake AP detection via unique SSID/BSSID counting (mdk3/mdk4) |
| **KRACK** | `algos.krack_detector` | Key Reinstallation Attack via EAPOL M3 replay detection (CVE-2017-13077) |
| **Karma/Pineapple** | `algos.karma_detector` | Detects APs responding to many unique SSIDs |
| **PMKID Harvesting** | `algos.pmkid_detector` | Dual-layer: Auth flood from random MACs + orphaned EAPOL M1 (hcxdumptool) |
| **WEP IV Attack** | `algos.wep_iv_detector` | IV collision and packet injection detection |

### Behavioral / Heuristic

| Detector | Module | Description |
|----------|--------|-------------|
| **Risk Scoring** | `algos.risk` | Configurable weighted risk engine with feature extraction |
| **RF Jamming** | `algos.jamming_detector` | Packet loss, RTS/CTS floods, anomalous RSSI |
| **Wardriving** | `algos.wardrive_detector` | Identifies mobile probe-request scanning patterns |

### Correlation

| Analyzer | Module | Description |
|----------|--------|-------------|
| **Exploit Chain** | `algos.exploit_chain_analyzer` | Links related detections into multi-stage attack chains |

## 2. Detection Pipeline

```mermaid
graph LR
    Frame[Raw Frame] --> Filter{Pre-Filter}
    Filter -->|Deauth| Deauth[Deauth Flood]
    Filter -->|Disassoc| Disassoc[Disassoc Flood]
    Filter -->|Beacon| Beacon[Beacon Flood]
    Filter -->|EAPOL| PMKID[PMKID Detector]
    Filter -->|EAPOL| KRACK[KRACK Detector]
    Filter -->|Mgmt Frame| Sig[Signature Engine]
    Filter -->|Metadata| Risk[Risk Engine]

    Deauth -->|Threshold| Alert[Alert Generation]
    Disassoc -->|Threshold| Alert
    Beacon -->|Threshold| Alert
    PMKID -->|Threshold| Alert
    KRACK -->|Replay| Alert
    Sig -->|Match| Alert
    Risk -->|Score > Threshold| Alert

    Alert --> Corr[Chain Analyzer]
    Corr -->|Chain Detected| ChainAlert[Chain Alert]
    Alert --> Dedupe{Deduplication}
    ChainAlert --> Dedupe
    Dedupe --> Upload[Controller Upload]
```

## 3. Tuning & Configuration
Detection sensitivity is configurable via `config/sensor.yaml`.
- `threshold_high`: Score > 90 (Immediate Critical Alert)
- `threshold_medium`: Score > 50 (Warning)
- `confirmation_window`: Time to wait for corroborating evidence (reduces flapping).
