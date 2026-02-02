# Sensor API Reference

> REST API documentation for the standalone Sentinel NetLab Sensor agent (`sensor/api_server.py`).
> For Controller API, see [Controller Ingestion API](api_ingest.md).

---

## Base URL

```
http://<sensor-ip>:5000
```

## API Overview

Sentinel NetLab uses two distinct APIs:

1.  **Controller API**: Central management (REST/OpenAPI). See [openapi.yaml](../reference/openapi.yaml) for the full specification.
2.  **Sensor API**: Internal local API for sensor management.

## Authentication

All Controller endpoints require headers:
- `X-API-Key`: For internal services (if configured) or Bearer tokens.
- `Authorization`: `Bearer <token>` (JWT) for users.

> [!WARNING]
> **Active Defense Endpoints**
> Endpoints related to "Active Defense" (e.g., `/api/v1/lab/attack`) are **ISOLATED**, **DISABLED BY DEFAULT**, and only available when `LAB_MODE=true`. See [Lab Mode](../lab_mode/mode_b_overview.md) for details. Do NOT use these in production.

## Sensor API (Internal)

**Header:**
```
X-API-Key: <your-api-key>
```

**Default Key:** `sentinel-dev-2024` (change in production)

---

## Endpoints Overview

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | ❌ | Health check |
| GET | `/status` | ❌ | Sensor status |
| GET | `/metrics` | ❌ | Prometheus metrics |
| GET | `/scan` | ✅ | Scan networks |
| GET | `/history` | ✅ | Historical data |
| GET | `/export/csv` | ✅ | Export CSV |
| GET | `/export/json` | ✅ | Export JSON |
| GET | `/forensics/events` | ✅ | Security events |
| POST | `/attack/deauth` | ✅ | Deauth attack |
| POST | `/attack/fakeap` | ✅ | Fake AP beacon |

---

## Core Endpoints

### GET `/health`

Health check endpoint. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-27T12:00:00",
  "interface": "wlan0",
  "metrics_url": "/metrics"
}
```

---

### GET `/status`

Get current sensor status and statistics.

**Response:**
```json
{
  "interface": {
    "name": "wlan0",
    "mode": "monitor",
    "channel": 6
  },
  "capture": {
    "running": true,
    "packets": 15420,
    "uptime": 3600
  },
  "storage": {
    "network_count": 25,
    "pcap_stats": {"files": 5, "size_mb": 128}
  }
}
```

---

### GET `/scan`

Perform network scan and return detected networks with risk scores.

**Rate Limit:** 10 requests per minute

**Response:**
```json
{
  "status": "success",
  "timestamp": "2026-01-27T12:05:00",
  "count": 2,
  "scan_duration": 4.5,
  "networks": [
    {
      "ssid": "Free_WiFi",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "signal": -45,
      "channel": 6,
      "encryption": "Open",
      "vendor": "TP-Link",
      "risk_score": 85,
      "risk_level": "High",
      "confidence": 0.92,
      "explain": {
        "encryption": 40.0,
        "signal": 12.0,
        "ssid_suspicion": 8.0
      }
    }
  ]
}
```

---

### GET `/export/csv`

Export scan data as CSV file.

**Response:** File download (`wifi_scan.csv`)

```csv
ssid,bssid,signal,channel,encryption,risk_score,risk_level
Free_WiFi,AA:BB:CC:DD:EE:FF,-45,6,Open,85,High
```

---

### GET `/export/json`

Export scan data as JSON file.

**Response:** File download (`wifi_scan.json`)

---

## Forensics Endpoints

### GET `/forensics/events`

Get security events (deauth detections, evil twins, etc).

**Response:**
```json
{
  "status": "success",
  "events": [
    {
      "timestamp": "2026-01-27T12:01:00",
      "type": "DEAUTH_FLOOD",
      "severity": "HIGH",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "message": "15 deauth frames in 5 seconds"
    }
  ]
}
```

---

## Attack Endpoints

> ⚠️ **Warning:** Requires `ALLOW_ACTIVE_ATTACKS=true` environment variable.

### POST `/attack/deauth`

Send deauthentication frames for testing.

**Request:**
```json
{
  "bssid": "AA:BB:CC:DD:EE:FF",
  "client": "FF:FF:FF:FF:FF:FF",
  "count": 10
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Deauth sent to AA:BB:CC:DD:EE:FF (10 frames)"
}
```

---

## Error Responses

| Code | Description |
|------|-------------|
| 401 | Unauthorized - Invalid or missing API key |
| 403 | Forbidden - Active attacks disabled |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |

**Error Format:**
```json
{
  "error": "Unauthorized"
}
```

---

## Python Client Example

```python
import requests

API_URL = "http://192.168.56.101:5000"
API_KEY = "sentinel-dev-2024"

def get_networks():
    response = requests.get(
        f"{API_URL}/scan",
        headers={"X-API-Key": API_KEY}
    )
    data = response.json()
    
    for net in data["networks"]:
        if net["risk_score"] >= 70:
            print(f"⚠️ HIGH RISK: {net['ssid']} ({net['risk_score']})")

if __name__ == "__main__":
    get_networks()
```

---

*Last Updated: January 2026*
