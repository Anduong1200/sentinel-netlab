# Risk Scoring Algorithm

The `RiskScorer` engine aggregates multiple weighted factors into a single threat score (0-100).

## 1. Scoring Formula

$$ Risk = \sum (w_i \times f_i) \times 100 $$

Where $w_i$ are configurable weights and $f_i$ are normalized feature values.

### Default Weights (Configurable)
- `encryption`: 0.3 (Insecure encryption is risky)
- `signal`: 0.2 (Anomalous signal strength)
- `vendor`: 0.2 (OUI mismatch or randomized MAC)
- `ssid`: 0.1 (Suspicious keywords like "Free WiFi")
- `wps`: 0.1 (WPS enabled is a vulnerability)
- `beacon`: 0.1 (Jitter or irregular intervals)

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
