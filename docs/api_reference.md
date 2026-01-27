# Sentinel NetLab API Reference

> Complete documentation for the Sentinel Sensor REST API.

## 🔑 Authentication

All API requests (except `/health`) require an API key passed in the header.

**Header:**
`X-API-Key: <your_api_key>`

Default key: `sentinel-2024` (Change this in production!)

---

## 📡 Core Endpoints

### 1. Health Check
Check if the API server is running. No auth required.

- **GET** `/health`

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-27T12:00:00"
}
```

### 2. Sensor Status
Get current operation status of the sensor.

- **GET** `/status`

**Response:**
```json
{
  "status": "running",
  "interface": "wlan0",
  "channel": 6,
  "engine": "tshark",
  "networks_detected": 15,
  "packets_captured": 10240,
  "uptime_seconds": 3600
}
```

---

## 📶 Network Data

### 3. Get Detected Networks
Retrieve list of all unique networks detected.

- **GET** `/networks`

**Parameters:**
- `sort_by` (optional): `rssi` | `risk` | `ssid` (default: `risk`)
- `limit` (optional): Number of results (default: 100)

**Response:**
```json
{
  "count": 2,
  "networks": [
    {
      "bssid": "AA:BB:CC:DD:EE:FF",
      "ssid": "Suspicious_WiFi",
      "channel": 11,
      "rssi": -45,
      "encryption": "Open",
      "risk_score": 90,
      "risk_details": ["Open Network", "High Signal Anomaly"],
      "last_seen": "2024-01-27T12:05:00"
    },
    {
      "bssid": "11:22:33:44:55:66",
      "ssid": "CoffeeShop",
      "channel": 1,
      "rssi": -70,
      "encryption": "WPA2",
      "risk_score": 10,
      "risk_details": [],
      "last_seen": "2024-01-27T12:04:55"
    }
  ]
}
```

### 4. Get Data Export
Export data in standard formats.

- **GET** `/export/<format>`
- **Format options**: `csv` | `json`

**Response (CSV):**
File download: `sensor_export_20240127.csv`

---

## ⚔️ Active Defense (Requires Permission)

> **⚠️ Warning**: These endpoints perform active packet injection.
> Requires `ALLOW_ACTIVE_ATTACKS=true` environment variable.

### 5. Deauthentication Attack
Send deauth frames to disconnect clients (for testing WIDS reaction).

- **POST** `/attack/deauth`

**Body:**
```json
{
  "bssid": "AA:BB:CC:DD:EE:FF",
  "count": 5,      // Number of packets (default: 1)
  "client": "FF:FF:FF:FF:FF:FF" // Target (default: Broadcast)
}
```

**Response:**
```json
{
  "status": "initiated",
  "target": "AA:BB:CC:DD:EE:FF",
  "type": "deauth",
  "cooldown": 10
}
```

---

## 🔍 Forensics & Logs

### 6. Get Security Events
Retrieve log of security incidents.

- **GET** `/forensics/events`

**Response:**
```json
{
  "events": [
    {
      "timestamp": "2024-01-27T12:01:00",
      "type": "EVIL_TWIN",
      "severity": "HIGH",
      "message": "Possible Evil Twin detected for SSID 'Corporate_WiFi'"
    },
    {
      "timestamp": "2024-01-27T11:55:00",
      "type": "DEAUTH_FLOOD",
      "severity": "MEDIUM",
      "message": "Deauth flood detected on Channel 6"
    }
  ]
}
```

---

## 🐍 Python Client Example

```python
import requests

API_URL = "http://localhost:5000"
HEADERS = {"X-API-Key": "sentinel-2024"}

def get_risky_networks():
    try:
        resp = requests.get(f"{API_URL}/networks", headers=HEADERS)
        data = resp.json()
        
        # Filter high risk
        risky = [n for n in data['networks'] if n['risk_score'] > 70]
        return risky
    except Exception as e:
        print(f"Error: {e}")
        return []

# Usage
risky_nets = get_risky_networks()
for net in risky_nets:
    print(f"ALERT: {net['ssid']} (Risk: {net['risk_score']})")
```

---

*Last updated: January 2024*
