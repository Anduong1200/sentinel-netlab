# WiFi Security Configuration & Attack Analysis

> Detailed assessment of wireless security standards, vulnerabilities, and attack mechanisms.

---

## 📊 1. Security Configuration Risk Matrix

The following table evaluates common WiFi configurations against modern attack vectors like **Evil Twin** and **Downgrade Attacks**.

| Protocol / Config | Risk Level | Primary Attack Vector & Mechanism | Mitigation & Trends |
| :--- | :--- | :--- | :--- |
| **Open** | **Critical** | **Sniffing / Evil Twin**: Traffic is unencrypted (plaintext). Attackers can easily intercept data or clone the AP. | Use **OWE (Opportunistic Wireless Encryption)** or VPN overlay. |
| **WEP / WPA-TKIP** | **Critical** | **Cracking**: Outdated encryption algorithms (RC4) broken since ~2001. Keys recovered in minutes via IV analysis. | **End-of-Life**. Must be disabled immediately to prevent forced downgrade. |
| **WPA2 (PSK)** | **High** | **Brute-Force / KRACK**: Vulnerable to 4-way handshake capture (offline dictionary attacks) and Key Reinstallation Attacks. | Use complex passwords (>12 chars). Patch firmware for KRACK. |
| **WPA2 (Enterprise)** | **Low** | **Rogue AP**: Harder to clone due to RADIUS authentication, but vulnerable to misconfigured clients trusting fake certs. | Standard for corporate environments. Enforce certificate validation. |
| **WPA3 (SAE)** | **Low** | **Resilient**: Uses dragonfly handshake (SAE) to prevent offline dictionary attacks. **PMF (Protected Management Frames)** is mandatory. | Current gold standard. Prevents most legacy attacks. |
| **Hidden SSID** | **Medium** | **False Security**: Network still broadcasts data; clients "probe" constantly, leaking location history. | **Not a security feature**. Should be disabled. |
| **PMF Disabled** | **Medium** | **Deauth / Disassociation**: Management frames are unencrypted, allowing attackers to disconnect users at will (DoS). | Enable **802.11w**. Essential for preventing forced disconnections used in Evil Twin setup. |
| **Legacy Mode** | **Critical** | **Downgrade Attack**: Allowing WPA/WEP enables attackers to force clients to use weaker protocols. | Disable "b/g" modes if possible; block WEP/WPA connections. |

---

## ⚔️ 2. Attack Mechanisms Explained

### 👾 Evil Twin Attack
**Concept**: An attacker creates a rogue Access Point with the same **SSID** (and often BSSID) as the legitimate network.
**Mechanism**: 
1.  Attacker jams/deauthenticates the real AP (using DoS).
2.  Victim disconnects and auto-reconnects to the stronger signal (the Evil Twin).
3.  Attacker intercepts traffic (Man-in-the-Middle) or presents a fake "Firmware Update" / "Login Page" to steal credentials.

> **Academic Insight**: *Development of a Client-Side Evil Twin Attack Detection System* (Nova SE Univ, 2018) proposes analyzing timing and signal variances to detect this from the client side.

### 📉 Downgrade Attack
**Concept**: Forcing a modern client to abandon robust protocols (WPA3/WPA2) for weaker ones (WPA/WEP) or weaker ciphers.
**Mechanism**:
1.  Attacker interferes with the handshake negotiation.
2.  Client/AP "agree" to fall back to a legacy protocol for compatibility.
3.  Attacker exploits the known vulnerabilities of the legacy protocol.

> **MITRE ATT&CK T1562.010**: Defines this tactic as manipulating the environment to reduce security posture.

---

## 🔬 3. Practical Assessment Methodology

To audit a network for these specific vulnerabilities using Sentinel NetLab:

### Reconnaissance
Use `airodump-ng` or Sentinel's `sensor` to capture Beacons. Analyze:
*   **Auth**: Is it PSK or MGT (Enterprise)?
*   **Cipher**: Is it CCMP (AES) or TKIP (Weak)?
*   **PMF**: Check RSN Capabilities field for `MFP Required` or `MFP Capable`.

### Active Testing (Authorized Only)
1.  **Downgrade Test**: Can a client connect if the AP only offers WPA1? (Simulate legacy AP).
2.  **Deauth Test**: Send deauth frames to a client. 
    *   *Result*: If client disconnects immediately -> **PMF Disabled** (Vulnerable).
    *   *Result*: If client ignores frames -> **PMF Enabled** (Secure).

### Evil Twin Simulation
1.  Set up a monitoring interface.
2.  Broadcast beacon frames with target SSID (using Scapy/mdk3).
3.  Monitor for client Probe Requests directed at the fake AP.
4.  **Note**: This effectively simulates the pre-conditions for an Evil Twin without executing the full attack.

---

## 📚 References

1.  **Comparison**: [FPT Shop - Evil Twin Assessment](https://fptshop.com.vn/tin-tuc/danh-gia/evil-twin-attack-188084)
2.  **Guide**: [Varonis - Evil Twin Defense](https://www.varonis.com/blog/evil-twin-attack)
3.  **WPA3**: [An Phat - WPA3 Security Analysis](https://www.anphat.vn/tin-cong-nghe/chuan-bao-mat-wpa3-bao-mat-manh-me)
4.  **Academic**: [NSU Works - Client-Side Evil Twin Detection](https://nsuworks.nova.edu/gscis_etd/1064/)
5.  **Tactics**: [MITRE ATT&CK - Downgrade Attacks](https://attack.mitre.org/techniques/T1562/010/)

---

*Document integrated into Sentinel NetLab Knowledge Base - January 2024*
