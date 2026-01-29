# WiFi Security Research

This section covers the research background for Sentinel NetLab.

## 802.11 Vulnerabilities
- **Management Frames**: Unencrypted in WPA2 (unless PMF/802.11w is used).
- **Deauthentication**: Attacks can disconnect users at will.
- **Evil Twins**: Clients auto-connect to strong signals with known SSIDs.

## Methodology
Our research focuses on:
1. Passive footprinting (listen-only).
2. Active auditing (only in lab environments).
3. Hybrid ML approaches to detect novel attacks.
