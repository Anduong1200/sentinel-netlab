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

### 2. Sensor Heartbeat
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
