# Rule-Based Detection

This module implements deterministic logic to identify specific attack signatures.

## 1. Evil Twin Detector (`algos.evil_twin`)
Detects Access Points impersonating legitimate networks.

### Logic
1. **SSID Sighting**: Tracks all unique (SSID, BSSID) pairs.
2. **Whitelist Check**: Ignores known-good BSSIDs.
3. **Mismatch Detection**:
    - Same SSID, Different BSSID (Potential twin).
    - Same SSID, Different Security (e.g., WPA2 Enterprise vs Open).
    - Same SSID, Significant Signal Jump (>20dBm).

### Configuration
```yaml
evil_twin:
  whitelist: ["aa:bb:cc:dd:ee:ff"]
  threshold_rssi_delta: 20
  ssid_similarity_threshold: 0.9
```

## 2. Deauthentication Flood (`algos.dos`)
Detects denial-of-service attempts using management frames.

### Logic
1. **Rate Volume**: Counts `DEAUTH` (Reason 7) and `DISASSOC` frames per second.
2. **Threshold**: If count > `threshold_per_sec` within `window_seconds`.
3. **Broadcast Detection**: Checks for `ff:ff:ff:ff:ff:ff` target address.

### Configuration
```yaml
dos:
  deauth_threshold: 10 # frames/sec
  window_seconds: 5
```
