# Signing Specification V1

This document defines the **Canonical String Format** and signing process for Sentinel NetLab telemetry ingestion.

## Requirements

*   **Hash Algorithm**: HMAC-SHA256
*   **Encoding**: Hex digest (lowercase)
*   **Timestamp Drift**: Server time ± 300 seconds (5 minutes)

## Canonical String Format

The string to sign is constructed by joining the following fields with a newline character (`\n`) and appending a final newline.

1.  **Method** (e.g., `POST`)
2.  **Path** (e.g., `/api/v1/telemetry`) - Resource path only, no query string or host.
3.  **Timestamp** (ISO 8601 UTC, e.g., `2023-10-27T10:00:00.123456+00:00`)
4.  **Sensor ID** (e.g., `sensor-01`)
5.  **Content Encoding** (e.g., `gzip` or `identity`)
6.  **Body Bytes** (Raw wire bytes)

**Format:**
```
{method}\n
{path}\n
{timestamp}\n
{sensor_id}\n
{content_encoding}\n
```
*Note: The metadata part ends with a newline. The Body Bytes are then appended directly.*

### Python Implementation Example

```python
parts = [
    method,             # "POST"
    path,               # "/api/v1/telemetry"
    timestamp,          # "2023-10-27T10:00:00.000000+00:00"
    sensor_id,          # "sensor-01"
    content_encoding    # "gzip"
]
canonical_meta = "\n".join(parts) + "\n"

h = hmac.new(secret_key.encode(), digestmod=hashlib.sha256)
h.update(canonical_meta.encode())
h.update(payload_bytes) # Raw bytes (compressed if gzip)
signature = h.hexdigest()
```

## Headers

The request MUST include the following headers:

| Header | Description | Example |
| :--- | :--- | :--- |
| `Authorization` | Bearer Token | `Bearer <token>` |
| `Content-Encoding`| Encoding of body | `gzip`, `identity` |
| `X-Timestamp` | ISO 8601 UTC Timestamp | `2023-10-27T10:00:00...` |
| `X-Sensor-ID` | ID of the sensor | `sensor-01` |
| `X-Signature` | HMAC-SHA256 Hex Digest | `a1b2c3d4...` |
| `X-Idempotency-Key`| Unique Batch ID (REQUIRED) | `sensor-01:1700000000` |

## Verification Logic (Fail-Closed)

1.  **Check Headers**: Reject if any required header is missing (400 Bad Request).
2.  **Check Timestamp**: Reject if `abs(server_time - X-Timestamp) > 300s` (400 or 401).
3.  **Check Encoding**: Reject if `Content-Encoding` is not `gzip` or `identity` (415 Unsupported Media Type).
4.  **Verify Signature**:
    *   Construct canonical string using request headers and **raw body bytes**.
    *   Compute HMAC-SHA256.
    *   Compare with `X-Signature` using constant-time comparison.
    *   Reject if mismatch (401 Unauthorized).
5.  **Decompress**: Only AFTER verification, decompress body if `gzip`.

83. **Response Semantics**:
84.
85. *   **Success (Async)**: `202 Accepted`
86.     *   JSON Body: `{"success": true, "status": "queued", "ack_id": "<batch_id>"}`
87. *   **Success (Duplicate)**: `200 OK`
88.     *   JSON Body: `{"success": true, "status": "duplicate", "ack_id": "<batch_id>"}`
89. *   **Rate Limited**: `429 Too Many Requests`
90.     *   Header: `Retry-After: <seconds>`
91. *   **Backpressure**: `503 Service Unavailable`
92.     *   Header: `Retry-After: <seconds>`
93. *   **Client Error**: `400/401/403` (Do not retry)
