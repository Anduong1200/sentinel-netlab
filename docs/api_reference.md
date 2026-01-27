# API Reference - WiFi Scanner Sensor

## Overview

RESTful API cho WiFi Scanner Sensor chạy trên Linux VM.

**Base URL:** `http://<VM_IP>:5000`  
**Authentication:** Header `X-API-Key`

---

## Endpoints

### GET /health

Health check endpoint (không cần authentication).

**Request:**
```bash
curl http://192.168.1.100:5000/health
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-27T12:00:00Z",
  "version": "1.0.0"
}
```

---

### GET /scan

Trigger WiFi scan và trả về danh sách networks.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `X-API-Key` | Yes | API authentication key |

**Request:**
```bash
curl -H "X-API-Key: student-project-2024" \
     http://192.168.1.100:5000/scan
```

**Response:**
```json
{
  "status": "success",
  "timestamp": "2026-01-27T12:00:00Z",
  "networks": [
    {
      "ssid": "Home_WiFi",
      "bssid": "AA:BB:CC:11:22:33",
      "channel": 6,
      "rssi": -48,
      "encryption": "WPA2-PSK",
      "vendor": "Apple",
      "risk_score": 25,
      "risk_level": "low",
      "first_seen": "2026-01-27T11:55:00Z",
      "last_seen": "2026-01-27T12:00:00Z",
      "beacon_count": 42
    },
    {
      "ssid": "Free_WiFi",
      "bssid": "11:22:33:44:55:66",
      "channel": 1,
      "rssi": -72,
      "encryption": "Open",
      "vendor": "Unknown",
      "risk_score": 92,
      "risk_level": "critical",
      "first_seen": "2026-01-27T11:58:00Z",
      "last_seen": "2026-01-27T12:00:00Z",
      "beacon_count": 15
    }
  ],
  "count": 2
}
```

**Error Response (401):**
```json
{
  "status": "error",
  "message": "Unauthorized - Invalid or missing API key"
}
```

---

### GET /history

Lấy scan history từ database.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Max records to return |
| `offset` | int | 0 | Pagination offset |

**Request:**
```bash
curl -H "X-API-Key: student-project-2024" \
     "http://192.168.1.100:5000/history?limit=50"
```

**Response:**
```json
{
  "status": "success",
  "networks": [...],
  "count": 50,
  "total": 150
}
```

---

### GET /export/csv

Export network data dưới dạng CSV.

**Request:**
```bash
curl -H "X-API-Key: student-project-2024" \
     http://192.168.1.100:5000/export/csv \
     -o networks.csv
```

**Response:** CSV file
```csv
SSID,BSSID,Channel,Encryption,Vendor,First Seen,Last Seen,Beacon Count,Best RSSI
Home_WiFi,AA:BB:CC:11:22:33,6,WPA2-PSK,Apple,2026-01-27T11:55:00Z,2026-01-27T12:00:00Z,42,-48
Free_WiFi,11:22:33:44:55:66,1,Open,Unknown,2026-01-27T11:58:00Z,2026-01-27T12:00:00Z,15,-72
```

---

### GET /export/json

Export network data dưới dạng JSON.

**Request:**
```bash
curl -H "X-API-Key: student-project-2024" \
     http://192.168.1.100:5000/export/json \
     -o networks.json
```

---

## Data Models

### Network Object

| Field | Type | Description |
|-------|------|-------------|
| `ssid` | string | Network name (empty = hidden) |
| `bssid` | string | MAC address (XX:XX:XX:XX:XX:XX) |
| `channel` | int | WiFi channel (1-14 for 2.4GHz) |
| `rssi` | int | Signal strength in dBm (-30 to -100) |
| `encryption` | string | Encryption type (Open, WEP, WPA, WPA2, WPA3) |
| `vendor` | string | OUI vendor lookup result |
| `risk_score` | int | Security risk score (0-100) |
| `risk_level` | string | Risk category (low, medium, high, critical) |
| `first_seen` | string | ISO 8601 timestamp |
| `last_seen` | string | ISO 8601 timestamp |
| `beacon_count` | int | Number of beacons received |

### Risk Levels

| Level | Score Range | Color |
|-------|-------------|-------|
| `low` | 0-39 | Green |
| `medium` | 40-69 | Yellow |
| `high` | 70-89 | Orange |
| `critical` | 90-100 | Red |

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid API key |
| 500 | Internal Server Error |

---

## Rate Limiting

- Default: 60 requests per minute
- Headers trả về: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## Examples

### Python Client

```python
import requests

API_URL = "http://192.168.1.100:5000"
API_KEY = "student-project-2024"

headers = {"X-API-Key": API_KEY}

# Scan
response = requests.get(f"{API_URL}/scan", headers=headers)
networks = response.json()["networks"]

for net in networks:
    print(f"{net['ssid']} ({net['encryption']}) - Risk: {net['risk_score']}")
```

### PowerShell

```powershell
$headers = @{"X-API-Key" = "student-project-2024"}
$response = Invoke-RestMethod -Uri "http://192.168.1.100:5000/scan" -Headers $headers
$response.networks | Format-Table ssid, encryption, risk_score
```
