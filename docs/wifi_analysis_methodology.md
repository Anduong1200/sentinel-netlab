# WiFi Management Frame Analysis Methodology

> Theoretical framework and technical basis for Sentinel NetLab's detection engine.

---

## 📡 1. Theory of Operation: Management Frames

Wireless Intrusion Detection Systems (WIDS) primarily rely on the analysis of **802.11 Management Frames**. Unlike Data Frames (which carry user payload and are often encrypted), Management Frames are responsible for network discovery, connection maintenance, and authentication.

This process operates on two mechanisms:
1.  **Passive Scanning**: The sensor silently listens for `Beacon Frames` broadcast by Access Points (APs).
2.  **Active Scanning**: The sensor (or a client) sends `Probe Requests`, and APs reply with `Probe Responses`.

Sentinel NetLab primarily utilizes **Passive Scanning** to minimize detection footprint.

### Data Extraction & Analysis

The following table details the key metadata extracted from Management Frames and their security significance:

| Information Element | Primary Source | Analysis Goal & Security Significance |
|---------------------|----------------|---------------------------------------|
| **SSID** (Network Name) | Beacon, Probe Response | Identifies the network. Detecting **Hidden SSIDs** (revealed in Probe Responses) or "Evil Twin" spoofing attempts. |
| **BSSID** (MAC Address) | All Frames | Unique identifier for the AP. Used for **location mapping**, differentiating multiple APs broadcasting the same SSID, and detecting spoofing (MAC cloning). |
| **RSSI** (Signal Strength) | RadioTap Header | Physical proximity indicator. Used for **heatmap generation**, defining "Safe Zones", and detecting potential leakage of signals outside secure areas. |
| **OUI** (Vendor ID) | BSSID (First 3 bytes) | Device fingerprinting. Helps identify **Rogue APs** (e.g., a consumer TP-Link Router appearing in a strictly Cisco Enterprise environment). |
| **Channel & Bandwidth** | Beacon (DS Parameter) | Network configuration analysis. Detects **channel overlapping** (DoS/Interference) or APs operating on unauthorized channels to evade detection. |
| **Security Capabilities** | Beacon (RSN IE) | Identifies encryption standards (Open, WEP, WPA2/3, Enterprise). **Critical**: Flags "Open" or "WEP" networks as high-risk vulnerabilities. |
| **Supported Rates / Std** | Beacon (HT/VHT/HE Caps) | Fingerprints AP capabilities (802.11n/ac/ax). Detecting legacy-only APs which may be vulnerable outdated hardware. |

---

## 🎓 2. Academic Context & Research Trends

Wireless analysis has evolved from simple "War Driving" to sophisticated behavioral analytics.

### Behavioral Analysis
Modern research moves beyond static signature matching. By analyzing the *timing* and *sequence* of frames, we can detect anomalies that encryption cannot hide.
*   **Example**: "Channel Hopping Behavior". Legitimate APs rarely change channels frequently. A device rapidly switching channels and sending Deauth packets is likely a **WIDS Sensor** or an **Attacker**.
*   **Case Study**: Researchers at Northeastern University recently uncovered vulnerabilities in **MU-MIMO** (Wi-Fi 5+) by analyzing MAC/PHY layer interactions, proving that protocol-level analysis remains a fertile ground for discovering new attack vectors.

### Fingerprinting & Geolocation
Combining **RSSI multilateration** with **Clock Skew analysis** (from Beacon timestamps) allows for highly accurate device identification and location tracking, even if MAC addresses are randomized.

### Automation & Machine Learning (The Sentinel Approach)
Sentinel NetLab aligns with the trend of **Automated Triage**. Instead of manually analyzing PCAP files in Wireshark, the system parses metadata in real-time and applies a **Risk Scoring Algorithm** (heuristic today, ML-ready for tomorrow) to surface only relevant threats to the operator.

---

## 🔬 3. Practical Methodology

To reproduce the analysis performed by Sentinel NetLab:

### Hardware Requirements
*   **WiFi Adapter**: Must support **Monitor Mode** and **Packet Injection** (e.g., Atheros AR9271, Realtek RTL8812AU).
*   **Antenna**: High-gain (5dBi+) recommended for wider coverage.

### Toolchain
1.  **Capture**: `airodump-ng` or `tcpdump` puts the interface into promiscuous monitor mode to capture all air traffic.
2.  **Parsing**: `Scapy` (Python) or `Tshark` dissects the raw 802.11 frames to extract Information Elements (IEs).
3.  **Analysis**: Python scripts correlate BSSIDs across channels, calculate average RSSI, and check OUI databases.

### Standard Workflow
1.  **Enable Monitor Mode**: `airmon-ng start wlan0`
2.  **Channel Hopping**: Cycle through channels 1-13 (2.4GHz) and 36-165 (5GHz) to ensure full spectrum visibility.
3.  **Frame Filtering**: Discard Data Frames (unless authorized for DPI) to save storage; focus on Type 0 (Management) and Type 1 (Control).
4.  **Aggregation**: Group frames by BSSID to build a "Session" view of the AP.

---

## ⚖️ 4. Legal & Ethical Considerations

While Management Frames are broadcast "in the clear", intercepting them is subject to legal restrictions.

*   **Passive vs. Active**: Passive listening is generally less legally risky than Active modification (Deauth/Jamming), but **Consent is Key**.
*   **Authorization**: You should only monitor networks you own or have written permission to audit.
*   **Privacy**: Avoid collecting Client Probe Requests if possible, as they can track individual movement (which serves as PII under GDPR).

> **Rule of Thumb**: "If it's not your network, don't capture it without a contract."

---

## 📚 References & Further Reading

1.  **Cisco Knowledge Base**: [The Significance of Beacon Frames](https://community.cisco.com/t5/wireless-mobility-knowledge-base/the-significance-of-beacon-frames-and-how-to-configure-the/ta-p/3132525)
2.  **EnGenius Tech**: [WiFi Beacon Frames Simplified](https://www.engeniustech.com/wi-fi-beacon-frames-simplified/)
3.  **Research Paper**: [Vulnerability of Wireless Networks (Northeastern Univ)](https://coe.northeastern.edu/news/francesco-restuccia-uncovers-the-vulnerability-of-wireless-networks/)
4.  **802.11 Standard**: [Management Frame Format](https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/)

---

*Document integrated into Sentinel NetLab Knowledge Base - January 2024*
