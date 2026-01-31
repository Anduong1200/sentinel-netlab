# API Ingestion Guide

## Endpoints

### 1. Telemetry Upload
**POST** `/api/v1/telemetry`

**Headers**:
- `Authorization: Bearer <api_key>`
- `Content-Type: application/json`
- `Content-Encoding: gzip` (optional, recommended)

**Body**: `TelemetryBatch` (see valid JSON in `docs/data_schema.md`)

**Responses**:
- `200 OK`: Batch accepted
  ```json
  {"status": "success", "processed_items": 50}
  ```
- `401 Unauthorized`: Invalid API Key
- `400 Bad Request`: Schema validation failure

### 2. Alert Upload
**POST** `/api/v1/alerts`

Real-time alert submission for critical security events.

**Body**: `AlertCreate`
```json
{
  "alert_type": "evil_twin",
  "severity": "High",
  "title": "Possible Evil Twin Detected",
  "description": "SSID 'CorpWiFi' seen with mismatched vendor OUI.",
  "bssid": "AA:BB:CC:DD:EE:FF",
  "evidence": {
    "rssi_delta": 20,
    "vendor_mismatch": true
  }
}
```

**Responses**:
- `200 OK`: Alert accepted
  ```json
  {"status": "success", "alert_id": "alert-12345"}
  ```
- `422 Unprocessable Entity`: Schema validation failure

### 3. Sensor Heartbeat
**POST** `/api/v1/heartbeat`

Used for status reporting and config updates.

**Body**:
```json
{
  "sensor_id": "sensor-01",
  "status": "online",
  "metrics": {
    "cpu_percent": 15.4,
    "uptime_seconds": 3600
  }
}
```

## Security Requirements
- **TLS 1.2+** required for all production deployments.
- **API Keys** should be rotated every 90 days.
- **Rate Limiting**: 60 requests/minute per sensor default.
