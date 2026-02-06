# API Contract Reference

> **REST API endpoints for Sentinel NetLab.**

---

## Base URL

| Profile | URL |
|---------|-----|
| Lab | `http://127.0.0.1:5000/api/v1` |
| Prod | `https://sentinel.example.com/api/v1` |

---

## Authentication

All endpoints require Bearer token authentication:

```http
Authorization: Bearer <token>
```

---

## Endpoints

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "profile": "lab",
  "timestamp": "2026-02-06T12:00:00Z"
}
```

---

### Sensors

#### List Sensors

```http
GET /sensors
```

**Response:**
```json
{
  "sensors": [
    {
      "id": "sensor-01",
      "name": "Lab Demo Sensor",
      "status": "online",
      "last_heartbeat": "2026-02-06T11:55:00Z"
    }
  ]
}
```

#### Register Sensor

```http
POST /sensors
Content-Type: application/json

{
  "id": "sensor-02",
  "name": "Office Sensor"
}
```

#### Sensor Heartbeat

```http
POST /sensors/{sensor_id}/heartbeat
```

---

### Telemetry

#### Ingest Telemetry

```http
POST /telemetry
Content-Type: application/json

{
  "sensor_id": "sensor-01",
  "batch_id": "batch-uuid",
  "frames": [
    {
      "timestamp": "2026-02-06T12:00:00Z",
      "bssid": "AA:BB:CC:11:22:33",
      "ssid": "CorpNet",
      "channel": 6,
      "rssi_dbm": -65,
      "security": "WPA2"
    }
  ]
}
```

**Response:**
```json
{
  "job_id": "job-uuid",
  "status": "queued",
  "frames_received": 1
}
```

#### Query Telemetry

```http
GET /telemetry?bssid=AA:BB:CC:11:22:33&since=2026-02-06T00:00:00Z&limit=100
```

---

### Alerts

#### List Alerts

```http
GET /alerts?status=open&severity=CRITICAL&limit=50
```

**Response:**
```json
{
  "alerts": [
    {
      "id": "ET-20260206-0001",
      "alert_type": "evil_twin",
      "severity": "HIGH",
      "ssid": "CorpNet",
      "bssid": "DE:AD:BE:EF:00:01",
      "reason_codes": ["DUPLICATE_SSID", "VENDOR_MISMATCH"],
      "created_at": "2026-02-06T12:00:00Z",
      "status": "open"
    }
  ],
  "total": 1
}
```

#### Get Alert Details

```http
GET /alerts/{alert_id}
```

#### Resolve Alert

```http
POST /alerts/{alert_id}/resolve
Content-Type: application/json

{
  "resolution": "false_positive",
  "notes": "Known AP, added to whitelist"
}
```

---

### Detector Status

```http
GET /detectors/status
```

**Response:**
```json
{
  "evil_twin": {
    "enabled": true,
    "alerts_generated": 42,
    "last_alert": "2026-02-06T11:30:00Z"
  },
  "deauth_flood": {
    "enabled": true,
    "alerts_generated": 5,
    "last_alert": "2026-02-06T10:15:00Z"
  }
}
```

---

## Error Responses

```json
{
  "error": "validation_error",
  "message": "sensor_id is required",
  "code": 400
}
```

| Code | Error | Description |
|------|-------|-------------|
| 400 | validation_error | Invalid request data |
| 401 | unauthorized | Missing/invalid token |
| 403 | forbidden | Insufficient permissions |
| 404 | not_found | Resource not found |
| 429 | rate_limited | Too many requests |
| 500 | internal_error | Server error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/telemetry` | 1000 req/min |
| `/alerts` | 100 req/min |
| `/sensors/*/heartbeat` | 60 req/min |
| Other | 100 req/min |
