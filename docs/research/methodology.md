# WiFi Management Frame Analysis Methodology

> Theoretical framework and technical basis for Sentinel NetLab's detection engine.

---

## 📡 1. Theory of Operation: Management Frames

Wireless Intrusion Detection Systems (WIDS) primarily rely on the analysis of **802.11 Management Frames**. Unlike Data Frames (which carry user payload and are often encrypted), Management Frames are responsible for network discovery, connection maintenance, and authentication.

This process operates on two mechanisms:
1.  **Passive Scanning**: The sensor silently listens for `Beacon Frames` broadcast by Access Points (APs).
2.  **Active Scanning**: The sensor (or a client) sends `Probe Requests`, and APs reply with `Probe Responses`.

Sentinel NetLab primarily utilizes **Passive Scanning** to minimize detection footprint.

### Comprehensive Data Extraction & Analysis

The following table details the critical data points extracted from 802.11 Management Frames, their source, and their role in network footprinting.

| Data Point | Relevant Frame Types | Purpose / What It Reveals |
| :--- | :--- | :--- |
| **SSID** | Beacon, Probe Response | Identifies WLAN. **Hidden SSIDs** are revealed in Association or active Probe Requests. |
| **BSSID** | All Management Frames | Unique AP MAC address. Crucial for **tracking**, **rogue AP detection**, and differentiating APs with same SSID. |
| **RSSI** | RadioTap Header | Estimates physical distance/coverage. Multi-point RSSI enables **triangulation** and physical heatmapping. |
| **Vendor / OUI** | Deduced from BSSID | Infers device type (e.g., Enterprise Cisco vs Consumer TP-Link), hinting at the network's purpose or legitimacy. |
| **Channel / Band** | Beacon, Probe Response | Shows operating frequency (2.4/5/6 GHz). Reveals channel planning quality or **interference**. |
| **Channel Hopping** | Deduced (Sequential) | Observing frequent channel changes can identify **misconfigured DFS** or evasive monitoring devices. |
| **Security (RSN IE)** | Beacon, Probe Response | Assesses security posture (WPA2/3 vs WEP). Weak protocols indicate high risk. |
| **Data Rates** | Beacon (HT/VHT/HE) | Infers AP generation (802.11n/ac/ax). Mandatory rates affect old client compatibility. |
| **Network Load** | Beacon (BSS Load IE) | Estimates station count and channel utilization (QBSS) for capacity and health analysis. |

---

## 🎓 2. Academic Context & Primary Sources

To build a rigorous research foundation, we rely on authoritative standards and peer-reviewed technical guides.

### 📚 Key Technical & Academic Sources

1.  **Official IEEE Standards**:
    *   **IEEE 802.11-2020**: The definitive specification for frame formats (Beacon, Probe, Auth).
    *   **IEEE 802.11bf** (Upcoming): Standards for WLAN Sensing, relevant for future behavioral analysis.
    *   *Source*: IEEE 802.11 Working Group & Standards Association.

2.  **Technical Analysis Guides**:
    *   **Cisco Wireless Security**: Deep dives into frame roles and RSN Information Elements.
    *   **CWNA/CWAP**: Certified Wireless Network Admin guides provide practical breakdown of IEs.

3.  **Research Applications**:
    *   **Topology Mapping**: Correlating BSSID + RSSI + Channel to map physical footprints.
    *   **Threat Detection**: Flagging deprecated security (WEP/TKIP) and detecting Rogue APs via OUI/SSID mismatches.

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

*Document integrated into Sentinel NetLab Knowledge Base - February 2026*
