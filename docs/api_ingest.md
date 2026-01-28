# Sensor → Controller Ingest API

> Data transport contract between sensors and the central controller

---

## Overview

Sensors collect WiFi frames, normalize them, and send batches to the controller via HTTPS POST.

```
Sensor                        Controller
  │                              │
  │  POST /api/v1/telemetry      │
  │  + Bearer Token              │
  │  + X-Signature (HMAC)        │
  │  + X-Timestamp               │
  │ ─────────────────────────►   │
  │                              │ Validate → Store → Score
  │      200 OK / 4xx / 5xx      │
  │ ◄─────────────────────────   │
```

---

## Endpoint

### POST `/api/v1/telemetry`

**Purpose**: Ingest batch of normalized frames from sensor.

**Headers**:

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <token>` |
| `Content-Type` | Yes | `application/json` |
| `X-Signature` | Recommended | HMAC-SHA256 of body |
| `X-Timestamp` | Recommended | ISO8601 UTC timestamp |
| `X-Sequence` | Recommended | Monotonic counter |

**Body**: `TelemetryBatch` JSON (see [Data Schema](data_schema.md))

---

## Request Example

```http
POST /api/v1/telemetry HTTP/1.1
Host: controller.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json
X-Signature: sha256=abc123...
X-Timestamp: 2026-01-28T10:30:00Z
X-Sequence: 42

{
  "sensor_id": "sensor-01",
  "batch_id": "batch-abc123",
  "timestamp_utc": "2026-01-28T10:30:00Z",
  "sequence_number": 42,
  "frames": [
    {
      "frame_id": "f1a2b3c4",
      "sensor_id": "sensor-01",
      "timestamp": 1706431800.123,
      "timestamp_iso": "2026-01-28T10:30:00.123Z",
      "mac_src": "AA:BB:CC:11:22:33",
      "mac_dst": "FF:FF:FF:FF:FF:FF",
      "bssid": "AA:BB:CC:11:22:33",
      "frame_type": "management",
      "frame_subtype": "beacon",
      "channel": 6,
      "rssi_dbm": -55,
      "ssid": "MyNetwork",
      "security": "wpa2_ccmp",
      "sequence_number": 1234,
      "is_encrypted": false,
      "frame_length": 256
    }
  ],
  "networks": [],
  "alerts": [],
  "frames_captured": 150,
  "frames_dropped": 0,
  "capture_duration_sec": 60.0
}
```

---

## Response

### Success (200 OK)

```json
{
  "success": true,
  "items_processed": 1,
  "ack_id": "ack-xyz789"
}
```

### Validation Error (400)

```json
{
  "error": "validation_error",
  "details": {
    "frames.0.bssid": "Invalid MAC address format"
  }
}
```

### Authentication Error (401)

```json
{
  "error": "unauthorized",
  "message": "Invalid or expired token"
}
```

### Rate Limited (429)

```json
{
  "error": "rate_limited",
  "retry_after": 60
}
```

---

## Security Requirements

### TLS

- **MUST** use HTTPS in production
- **MUST** validate server certificate (`verify=True`)
- **NEVER** set `verify=False` except for local development

### Authentication

1. **Bearer Token** (minimum):
   ```
   Authorization: Bearer <token>
   ```

2. **mTLS** (recommended for production):
   - Sensor presents client certificate
   - Controller verifies against CA

### Message Signing

For tamper protection, include HMAC signature:

```python
import hmac
import hashlib

body = json.dumps(payload).encode()
signature = hmac.new(
    secret.encode(),
    body,
    hashlib.sha256
).hexdigest()

headers["X-Signature"] = f"sha256={signature}"
```

### Replay Protection

Include monotonic sequence number:
- Controller tracks last sequence per sensor
- Rejects if `sequence <= last_seen`

---

## Error Handling

| Status | Action |
|--------|--------|
| 200 | Success, clear queue |
| 400 | Log error, drop invalid frames |
| 401 | Re-authenticate, retry |
| 429 | Exponential backoff (30s, 60s, 120s) |
| 5xx | Retry with jitter (max 3 attempts) |

### Retry Strategy

```python
import random
import time

def send_with_retry(payload, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = send(payload)
            if response.status_code == 200:
                return True
            if response.status_code == 429:
                retry_after = response.json().get("retry_after", 60)
                time.sleep(retry_after + random.uniform(0, 5))
            elif response.status_code >= 500:
                time.sleep((2 ** attempt) + random.uniform(0, 1))
        except ConnectionError:
            time.sleep((2 ** attempt) + random.uniform(0, 1))
    
    # Queue for later
    save_to_offline_queue(payload)
    return False
```

---

## Offline Queue

When controller is unreachable:

1. Store failed batches to local SQLite
2. Retry on next successful connection
3. Expire batches after 24 hours

---

## Alert Ingestion

### POST `/api/v1/alerts`

Separate endpoint for high-priority alerts:

```json
{
  "alert_id": "alert-123",
  "sensor_id": "sensor-01",
  "alert_type": "evil_twin",
  "severity": "High",
  "title": "Evil Twin Detected",
  "description": "Same SSID with different BSSID",
  "bssid": "DE:AD:BE:EF:00:01",
  "ssid": "CorpNet",
  "evidence": {"frame_count": 15},
  "risk_score": 85.0,
  "mitre_attack": "T1557.001"
}
```

---

## See Also

- [Data Schema](data_schema.md)
- [OpenAPI Spec](api-openapi.yaml)
- [Architecture](architecture.md)
