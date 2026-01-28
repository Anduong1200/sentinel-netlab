# Threat Model for Sentinel NetLab (v1.1)

## 1. System Overview
Sentinel NetLab is a distributed Wireless Intrusion Detection System (WIDS) designed for academic and security assessment purposes. It monitors 802.11 traffic to detect anomalies and potential attacks.

## 2. Protected Assets
- **Wireless Infrastructure**: Access Points (APs), Routers, and legitimate Clients.
- **Data Privacy**: User traffic (though Sentinel only inspects headers, not payloads).
- **Sensor Integrity**: ensuring sensors are not subverted by attackers.

## 3. Threat Landscape & Attack Surfaces

### A. Wireless Threats (Scope of Detection)
Sentinel is designed to detect the following attacks (aligned with OWASP & MITRE ATT&CK):

| Threat | Description | MITRE ID | Detection Capability |
| :--- | :--- | :--- | :--- |
| **Evil Twin / Rogue AP** | Attacker mimics a legitimate AP to intercept creds. | T1557.002 | **High** (via `AdvancedEvilTwinDetector`) |
| **Deauthentication** | Flooding management frames to disconnect clients. | T1498.001 | **High** (via `DoSDetector`) |
| **Beacon Flooding** | Flooding fake SSIDs to confuse scanners/drivers. | T1498.001 | **High** (via `DoSDetector`) |
| **Weak Encryption** | Usage of OPN/WEP networks. | T1040 | **High** (via `RiskScorer`) |
| **Karma Attack** | Responding to probe requests from clients. | T1557.001 | **Medium** (via Client Probing analysis) |

### B. System Threats (Risks to Sentinel itself)
| Threat | Risk | Mitigation |
| :--- | :--- | :--- |
| **Sensor Spoofing** | Attacker impersonates a sensor to feed false data. | Authentication tokens & HMAC signing (Planned) |
| **API DoS** | Flooding the controller API. | Rate limiting (Redis-based) |
| **Database Injection** | Malicious SSID strings injecting SQL/HTML. | SQLAlchemy ORM & Auto-escaping in Dash |
| **Physical Tampering** | Theft of sensor hardware. | Disk encryption (OS level) - Out of scope for app |

## 4. Trust Boundaries
1.  **Untrusted**: The wireless air interface (802.11 frames). All input must be treated as hostile.
2.  **Semi-Trusted**: The management network connecting Sensors to Controller.
3.  **Trusted**: The internal Controller processing environment (Docker containers).

## 5. Risk Assessment (v1.1)
- **High**: Lack of mutual TLS between Sensor and Controller (Roadmap v1.2).
- **Medium**: False positives in high-density environments (Requires ML tuning).
- **Low**: Dashboard XSS from malicious SSIDs (Mitigated by React/Dash architecture).

## 6. Security Controls
- **Input Validation**: Strict parsing of 802.11 headers (Scapy/Tshark).
- **Authentication**: API Keys for sensors, Basic Auth for Dashboard (via Reverse Proxy).
- **Active Defense Safety**: `LabSafetyChecker` requires `SENTINEL_LAB_MODE=true` and `SENTINEL_AUTH_KEY`.

---
*Last Updated: 2026-01-28*
