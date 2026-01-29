# Detection Algorithms

Sentinel NetLab isolates threats using a multi-stage pipeline.

## 1. Signature-Based Detection
- **Deauth Flood**: Counts unauthenticated deauth frames per second (Threshold-based).
- **Probing**: Detects high-volume probe requests from single source.

## 2. Stateful Detection
- **Evil Twin**: Correlates SSID + BSSID + Signal Strength (RSSI).
  - If a known SSID appears with a different BSSID or significantly different signal characteristics/channel, it is flagged.

## 3. Anomaly Detection (ML)
- **Autoencoder**: Models normal traffic patterns (size, frequency, subtypes).
- **Reconstruction Error**: High error indicates anomaly (e.g., fuzzing, unknown attack patterns).
