# Risk Scoring Algorithm

The `RiskScorer` engine aggregates multiple weighted factors into a single threat score (0-100).

## 1. Scoring Formula

$$ Risk = \sum (w_i \times f_i) \times 100 $$

Where $w_i$ are configurable weights and $f_i$ are normalized feature values.

### Default Weights (Configurable)
- `encryption`: 0.30 (Insecure encryption is risky)
- `rssi_norm`: 0.10 (Strong signal anomaly)
- `vendor_risk`: 0.15 (Unknown/Suspicious OUI)
- `ssid_suspicion`: 0.15 (Phishing patterns)
- `wps_flag`: 0.05 (WPS enabled)
- `beacon_anomaly`: 0.10 (Timing jitter)
- `hidden_ssid`: 0.05 (Hidden network)
- `channel_crowd`: 0.05 (Unusual channel)
- `temporal`: 0.05 (New network appearance)

## 2. Feature Normalization

### Encryption ($f_{enc}$)
- **WPA3**: 0.0 (Secure)
- **WPA2**: 0.3 (Standard)
- **WEP**: 0.8 (Broken)
- **Open**: 1.0 (Insecure)

### Signal / RSSI ($f_{rssi}$)
Calculated as deviation from baseline or proximity to sensor.
- $Sig > -40dBm$ (Very Close): 1.0
- $Sig < -80dBm$ (Far): 0.1

### Vendor ($f_{vendor}$)
- **Valid OUI**: 0.0
- **Randomized/Unknown**: 0.5
- **Blacklisted OUI**: 1.0

## 3. Thresholds
Alerts are triggered based on the composite score:
- **Critical**: Score > 90 (Immediate action)
- **High**: Score > 75 (Review required)
- **Medium**: Score > 50 (Warning)

## 4. Explainability
Every risk score includes an `evidence` object detailing which factors contributed to the score, e.g., `{"encryption": "Open", "signal": -35dBm}`.
