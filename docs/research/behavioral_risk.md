# Behavioral Risk Analysis & Rogue AP Detection

> Framework for detecting anomalies based on signal behavior, beyond static signatures.

---

## 📊 1. Behavioral Risk Indicators

This framework classifies risks based on the *behavior* of wireless signals, offering a layer of detection that standard signature matching misses.

| Behavioral Indicator | Detection Method | Risk Type / Goal | Attack Classification (MDPI 2025) |
| :--- | :--- | :--- | :--- |
| **Signal Leakage** | Compare real-time RSSI vs. calculated Safe Zone threshold. Heatmap analysis. | **Physical Leakage**: Signal extending beyond physical security perimeter (e.g., parking lot). | **Passive Attack**: Remote attackers can capture handshakes without entering premises. |
| **SSID Duplication** | Detect multiple BSSIDs (MACs) broadcasting the same SSID. Correlate with OUI/Channel. | **Evil Twin / Rogue AP**: Fake AP luring users. | **Active Attack**: Active interception of user traffic. |
| **Beacon Anomalies** | Monitor `Beacon Interval` (BI) consistency and `Timestamp` clock skew. | **Fake AP / Software AP**: Tools like `hostapd` or `Pineapple` often have imprecise beacon timing vs. hardware APs. | **Active Attack**: Mimicking legitimate infrastructure. |
| **Shadow IT / Strange SSID** | Whitelist comparison. Alert on *any* unknown SSID > -80dBm inside the premises. | **Unmanaged Risk**: Unauthorized devices bridging secure/insecure networks. | **Active/Passive**: Depends on intent (Employee device vs. Implant). |

---

## 🎓 2. Academic Framework: Active vs. Passive Attacks

Based on recent research ("Secure WiFi Sensing Technology", *MDPI Sensors 2025*), we categorize threats to wireless sensing systems into:

### Passive Attacks (Eavesdropping)
*   **Mechanism**: Attacker listens silently. No signal injection.
*   **Defense**: **Signal Containment**. Ensuring AP power levels are tuned so signals do not "bleed" into public areas. RSSI monitoring detects when an internal AP is broadcasting too "loudly" or if a rogue device is placed at the perimeter.

### Active Attacks (Intervention)
*   **Mechanism**: Attacker transmits signals (Beacons, Deauths).
*   **Defense**: **Anomaly Detection**.
    *   **Evil Twin**: Two strong signals with same SSID.
    *   **Beacon Spoofing**: Inconsistent sequence numbers or timestamps.

---

## 🔬 3. Modern Research Approaches

Moving beyond simple "Blacklisting", modern WIDS adopt:

### Network Behavior Analysis (NBA)
Establishing a **baseline** of "Normal":
*   Average traffic volume per AP.
*   Standard client count.
*   Time-of-day activity patterns.
*   *Detection*: Use algorithmic anomaly detection (e.g., Isolation Forest) to flag deviations from this baseline.

### Device Fingerprinting
Identifying specific hardware using micro-behaviors:
*   **Clock Skew**: Slight drift in Beacon Timestamps unique to each crystal oscillator.
*   **IE Ordering**: The specific order of Information Elements in beacon frames varies by vendor/firmware.
*   *Application*: Distinguish a legitimate Cisco AP from a Raspberry Pi spoofing its MAC address.

> **Keywords for Research**: "WiFi fingerprinting", "802.11 beacon anomaly detection", "clock skew based identification".

---

## 🛠️ 4. Practical Implementation with Sentinel NetLab

To implement behavioral monitoring:

### Step 1: Establish Whitelist (Baseline)
Use the sensor to scan the environment for 24h and build a list of authorized devices:
```json
{
  "authorized_ssids": ["Corp_WiFi", "Corp_Guest"],
  "authorized_bssids": ["AA:BB:CC:*:*:*"],
  "rssi_threshold": -75,
  "safe_channels": [1, 6, 11]
}
```

### Step 2: Real-time Monitoring
Poll sensor data (`/scan` endpoint) and apply logic:

*   **Rule 1 (Leakage)**: `IF ssid == "Corp_Internal" AND rssi > -60 (in lobby) THEN Alert("Signal Leakage")`
*   **Rule 2 (Evil Twin)**: `IF ssid == "Corp_WiFi" AND bssid NOT IN whitelist THEN Alert("Rogue AP Detected")`
*   **Rule 3 (Anomaly)**: `IF channel NOT IN safe_channels THEN Alert("Unexpected Channel Usage")`

### Step 3: Advanced Analysis (Future Work)
Export data to CSV/JSON and use Python `scikit-learn` to train an anomaly detection model on Beacon Intervals and RSSI variance.

---

## 📚 References

1.  **MDPI Sensors 2025**: [Secure WiFi Sensing Technology](https://www.mdpi.com/1424-8220/25/6/1913) - Active vs Passive Attack Framework.
2.  **CafeF News**: [Risk of Public WiFi](https://cafef.vn/rui-ro-moi-khi-dung-mang-wifi-cong-cong-188251201132749308.chn) - Context for passive data collection risks.
3.  **Research Topic**: "Rogue AP Detection via Clock Skew" (Generic academic reference).

---

*Document integrated into Sentinel NetLab Knowledge Base - February 2026*
