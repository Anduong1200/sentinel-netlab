# Risk Scoring Model & Feature Engineering

> Mathematical framework for quantifying Wi-Fi security risks, transforming qualitative metadata into actionable numerical scores.

---

## 📊 1. Risk Factors (Qualitative → Quantitative)

We categorize risk factors into **Static** (Configuration) and **Dynamic** (Behavioral) features. Each feature is normalized to a `[0, 1]` vector.

### A. Static Features (Configuration)

| Feature | Description | Quantization Logic (0.0 - 1.0) |
| :--- | :--- | :--- |
| **Encryption** | Security Protocol | Open=1.0, WEP=0.9, WPA/TKIP=0.5, WPA2=0.2, WPA3=0.0 |
| **Vendor Risk** | OUI Trust Level | Unknown=0.5, Consumer (TP-Link/D-Link)=0.3, Enterprise (Cisco/Aruba)=0.0 |
| **WPS Enabled** | WiFi Protected Setup | **1.0** if enabled (major vulnerability), 0.0 otherwise |
| **Hidden SSID** | Network Visibility | **1.0** if hidden (false security), 0.0 otherwise |
| **SSID Suspicion** | Pattern Matching | Regex match ("Free", "Public", "Guest") → 0.2 to 1.0 depending on keyword |

### B. Dynamic Features (Behavioral)

| Feature | Description | Normalization Formula |
| :--- | :--- | :--- |
| **Signal Strength** | RSSI Proximity | `x_rssi = clamp((RSSI + 100) / 50, 0, 1)` <br> Stronger signal (-50dBm) = Higher risk weight |
| **Beacon Anomaly** | Interval Consistency | `x_beacon = min(1, abs(interval - 100TU) / 100TU)` |
| **Client Ratio** | Active Associations | `x_clients = 1.0` if Signal > -60dBm AND Clients == 0 (Potential Rogue) |
| **Channel Crowd** | Interference | `x_crowd = min(1, AP_count_on_channel / 10)` |

---

## 🧮 2. Scoring Algorithm

We utilize a **Weighted Linear Model** for explainability (White-box AI), suitable for SOC integration.

### Formula
$$ S_{raw} = \sum_{i=1}^{N} (w_i \cdot x_i) $$

Where $w_i$ is the weight of feature $i$, and $x_i$ is the normalized feature value.

### Default Weights (Calibrateable)

```yaml
weights:
  encryption: 0.40      # Critical impact
  rssi_norm: 0.15       # Physical proximity
  beacon_anomaly: 0.12  # Technical spoofing indicator
  vendor_risk: 0.10     # Hardware quality
  ssid_suspicion: 0.08  # Social Engineering
  wps_flag: 0.06        # Legacy brute-force risk
  hidden_flag: 0.05     # Obscurity
  channel_crowd: 0.04   # Environment
```

### Output Normalization
The final Risk Score ($Score_{final}$) is scaled to **0 - 100**:

*   **0 - 39**: **LOW** (Safe / Enterprise WPA2/3)
*   **40 - 69**: **MEDIUM** (Misconfigured / Weak Password suspicion)
*   **70 - 100**: **HIGH** (Open / WEP / Rogue AP / Active Attack)

---

## 🤖 3. Confidence Metric

To prevent false positives on partial data, we calculate a **Confidence Score ($C$)**:

$$ C = \frac{\text{Count(Available Features)}}{\text{Total Features}} $$

*   If $C < 0.5$: The system flags "Low Confidence" (Insufficient Data).
*   Typically requires: Beacon capture (Basic) + Probe capture (Advanced) to reach $C > 0.8$.

---

## 📝 4. JSON Output Schema

The API `/scan` endpoint returns this structured object for SIEM integration:

```json
{
  "ssid": "Corp_Guest",
  "bssid": "AA:BB:CC:11:22:33",
  "score": 67,
  "label": "MEDIUM",
  "confidence": 0.82,
  "features": {
    "enc_score": 0.2,
    "rssi_norm": 0.8,
    "wps_flag": 0.0
  },
  "explain": {
    "encryption": 8.0,      // (0.2 * 0.40 * 100)
    "rssi": 12.0,           // (0.8 * 0.15 * 100)
    "vendor": 5.0
  }
}
```

*   **explain**: Shows exactly *why* an AP got its score, allowing analysts to trust the result.

---

## 📈 5. Future Roadmap: Machine Learning

While the current heuristic model is robust for known threats, we plan to implement:
1.  **Logistic Regression**: To learn weights $w_i$ automatically from labeled datasets.
2.  **Isolation Forest**: For purely anomaly-based detection (e.g., detecting new attack tools that don't match known signatures).

---

*Document integrated into Sentinel NetLab Knowledge Base - February 2026*
