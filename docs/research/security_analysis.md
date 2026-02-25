# WiFi Security Configuration & Attack Analysis

> Detailed assessment of wireless security standards, vulnerabilities, and attack mechanisms.

---

## 📊 1. Security Configuration Risk Matrix

The following table evaluates common WiFi configurations against modern attack vectors like **Evil Twin** and **Downgrade Attacks**.

## 📊 1. Comprehensive Security Risk Matrix

The following table synthesizes risk levels based on IEEE standards and modern attack vectors.

| Protocol / Standard | Risk Level | Primary Vulnerability & Mechanic | Academic Context / Mitigation |
| :--- | :--- | :--- | :--- |
| **Open (No Encryption)** | **Critical** | **Eavesdropping / ARP Poisoning**: Plaintext transmission allows trivial MITM. | **OWE (RFC 8110)** encrypts open networks. |
| **WEP / WPA-TKIP** | **Critical** | **IV Collision / Beck-Tews**: RC4 stream cipher flaws allow key recovery in minutes (aircrack-ng). | **Deprecated (2004)**. Must be disabled to prevent downgrade. |
| **WPA2-PSK (Weak Pwd)** | **High** | **Dictionary Attack**: 4-Way Handshake capture allows offline cracking of the PMK. | **KRACK (2017)**: Key Reinstallation Attack exploits handshake state machine. |
| **WPA2 (Enterprise)** | **Low** | **Rogue AP**: Vulnerable if clients accept invalid server certificates (EAP-PEAP). | **EAP-TLS**: Client-side certificates mitigate Rogue AP risks. |
| **WPA3-SAE** | **Low** | **Side-Channel**: Early implementations vulnerable to **Dragonblood** (cache-timing). | **SAE (Dragonfly)**: Resistant to offline decoding. **PMF** prevents deauth floods. |
| **Hidden SSID** | **Medium** | **False Security**: Clients probe constantly, leaking PII (location history). | **Security through Obscurity**: Ineffective against probe sniffing. |
| **PMF Disabled** | **High** | **Deauth Flooding**: Management frames disjoint from encryption, allowing DoS. | **802.11w**: Cryptographically protects deauth frames. Mandatory in WPA3. |
| **Legacy Compatibility** | **Critical** | **Downgrade Attack**: Protocol negotiation manipulation (see MITRE T1562.010). | **Disable "b/g" modes**. Force WPA2/3-only Mode. |

---

## ⚔️ 2. Advanced Attack Analysis

### 🐉 WPA3 & Dragonblood Side-Channels
While WPA3 uses the **Simultaneous Authentication of Equals (SAE)** handshake to prevent dictionary attacks, it is not immune to side-channel analysis.
*   **Mechanism**: The *Dragonfly* handshake involves complex ECC operations. Early implementations leaked timing information or cache access patterns, allowing attackers to infer the password (so-called **Dragonblood** vulnerabilities).
*   **Defense**: Implementation patching (constant-time execution).

### 🛡️ Protected Management Frames (PMF / 802.11w)
Classic WiFi attacks rely on sending forged `Deauthentication` frames to disconnect a user. This is a prerequisite for:
1.  Capturing a WPA2 Handshake (when user reconnects).
2.  Forcing migration to an Evil Twin (automigration).
*   **Impact**: If PMF is **Disabled**, detection systems will see valid deauth frames but cannot verify their specific authenticity.
*   **Status**: Mandatory for WPA3 certification.

### 📉 Downgrade Attacks (Protocol Rolling)
Attackers actively interfere with the association process to block WPA2/3 advertisements.
*   **Goal**: Force client to use WEP or WPA-TKIP.
*   **Vector**: Jamming 802.11n/ac beacons or falsifying capabilities.

---

## 🔬 3. Practical Assessment Methodology

### Toolchain Reference
*   **Standard**: `airodump-ng`, `wireshark`
*   **Advanced**:
    *   `hostapd-mana`: Advanced Rogue AP for Evil Twin simulation.
    *   `krackattacks-scripts`: Vanhoef's suite for testing Key Reinstallation vulnerabilities.
    *   `dragonslayer`: Specialized tool for WPA3 SAE analysis.

### Reconnaissance Checklist
1.  **PMF Check**: Look for `RSN Capabilities: MFP Required` in Beacon frames.
2.  **Cipher Check**: Flag any `GROUP CIPHER: TKIP` or `BSS Basic Rates` containing legacy speeds (1, 2, 5.5, 11 Mbps).
3.  **WPS Status**: Check if **WiFi Protected Setup (WPS)** is unlocked (vulnerable to Pixie Dust).

### Active Testing (Authorized Only)
1.  **Deauth Resilience**:
    *   Send 10 deauth frames.
    *   *Secure*: Client stays connected (PMF Active).
    *   *Insecure*: Client disconnects instantly.
2.  **Downgrade Simulation**:
    *   Set up AP with same SSID but WPA1-only.
    *   Verify if clients auto-connect (Risk mitigation: Client should prefer WPA2).

---

## 📚 References

1.  **Comparison**: [FPT Shop - Evil Twin Assessment](https://fptshop.com.vn/tin-tuc/danh-gia/evil-twin-attack-188084)
2.  **Guide**: [Varonis - Evil Twin Defense](https://www.varonis.com/blog/evil-twin-attack)
3.  **WPA3**: [An Phat - WPA3 Security Analysis](https://www.anphat.vn/tin-cong-nghe/chuan-bao-mat-wpa3-bao-mat-manh-me)
4.  **Academic**: [NSU Works - Client-Side Evil Twin Detection](https://nsuworks.nova.edu/gscis_etd/1064/)
5.  **Tactics**: [MITRE ATT&CK - Downgrade Attacks](https://attack.mitre.org/techniques/T1562/010/)

---

*Document integrated into Sentinel NetLab Knowledge Base - February 2026*
