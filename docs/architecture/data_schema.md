# Data Schema

## Telemetry Item
Represents a unique WiFi access point or station observation.

| Field | Type | Description |
|-------|------|-------------|
| `bssid` | string | MAC address (anonymized if privacy enabled) |
| `ssid` | string | Network name (UTF-8) |
| `rssi_dbm` | int | Signal strength in dBm (-100 to 0) |
| `channel` | int | WiFi channel (1-14, 36-165) |
| `timestamp` | iso8601 | Capture time (UTC) |
| `security` | enum | `open`, `wep`, `wpa`, `wpa2`, `wpa3` |
| `capabilities` | object | detailed flags (privacy, wps, pmf) |

## API Payload (Batch)
Batched telemetry upload format.

```json
{
  "sensor_id": "sensor-01",
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-03-20T10:00:00Z",
  "items": [
    {
      "bssid": "aa:bb:cc:11:22:33",
      "ssid": "Guest_Network",
      "rssi_dbm": -65,
      "channel": 6,
      "security": "wpa2"
    }
  ]
}
```

## Privacy Modes
1. **Normal**: Raw MAC addresses stored for forensics.
2. **Anonymized** (Default): MACs hashed with salted SHA-256 or truncated. `store_raw_mac: false` config.
3. **Private**: SSIDs also redacted.
