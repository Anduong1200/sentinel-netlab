# API Reference - WiFi Scanner Sensor

## Overview

RESTful API cho WiFi Scanner Sensor chạy trên Linux VM.

**Base URL:** `http://<VM_IP>:5000`  
**Authentication:** Header `X-API-Key`

---

## Endpoints

### GET /health

Health check endpoint (không yêu cầu authentication).

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-27T10:00:00.000000",
  "interface": "wlan0"
}
```

---

### GET /status

Sensor status với thông tin interface và capture state.

**Response:**
```json
{
  "interface": {
    "interface": "wlan0",
    "exists": true,
    "mode": "managed",
    "monitor_capable": true
  },
  "capture": {
    "is_running": false,
    "total_packets": 0
  },
  "storage": {
    "network_count": 15,
    "pcap_stats": {"count": 3, "total_size_mb": 12.5}
  }
}
```

---

### GET /scan

Trigger WiFi scan và trả về kết quả.

**Headers:**
| Header | Value |
|--------|-------|
| `X-API-Key` | `student-project-2024` |

**Rate Limit:** 10 requests/minute

**Response:**
```json
{
  "status": "success",
  "timestamp": "2026-01-27T10:00:00.000000",
  "count": 5,
  "networks": [
    {
      "ssid": "Home_Network",
      "bssid": "AA:BB:CC:11:22:33",
      "signal": -55,
      "channel": 6,
      "encryption": "WPA2-PSK",
      "vendor": "TP-Link",
      "risk_score": 45,
      "risk_level": "medium"
    }
  ]
}
```

---

### GET /history

Lấy lịch sử scan (50 networks gần nhất).

**Headers:** `X-API-Key`

**Response:**
```json
{
  "networks": [
    {
      "ssid": "...",
      "bssid": "...",
      "first_seen": "2026-01-27T09:00:00",
      "last_seen": "2026-01-27T10:00:00",
      "signal": -60,
      "channel": 1,
      "encryption": "WPA2",
      "risk_score": 50
    }
  ]
}
```

---

### GET /export/csv

Export data dạng CSV file.

**Headers:** `X-API-Key`

**Response:** CSV file download

```
SSID,BSSID,Signal,Channel,Encryption,Risk Score
Home_Network,AA:BB:CC:11:22:33,-55,6,WPA2,45
```

---

### GET /export/json

Export data dạng JSON file.

**Headers:** `X-API-Key`

**Response:** JSON file download

---

## Error Responses

| Code | Meaning |
|------|---------|
| 401 | Unauthorized - Invalid or missing API key |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |

**Error Response Format:**
```json
{
  "error": "Unauthorized"
}
```

---

## Client Example (Python)

```python
import requests

API_URL = "http://192.168.56.101:5000"
API_KEY = "student-project-2024"

headers = {"X-API-Key": API_KEY}

# Scan
response = requests.get(f"{API_URL}/scan", headers=headers, timeout=30)
data = response.json()
print(f"Found {data['count']} networks")
```

## Client Example (cURL)

```bash
curl -H "X-API-Key: student-project-2024" http://VM_IP:5000/scan
```
