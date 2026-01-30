# Telemetry Integrity & Security

Sentinel NetLab employs a multi-layered approach to ensure the integrity, authenticity, and confidentiality of sensor data.

## 1. Message Signing (HMAC)
All telemetry batches and alerts are signed using **HMAC-SHA256**.

### Mechanism
1. **Canonical String**: `method + path + timestamp + sequence + payload`
2. **Key**: Shared secret `CONTROLLER_HMAC_SECRET` (Env var)
3. **Header**: `X-Signature: <hex_digest>`

This prevents:
- **Tampering**: Modifying payload in transit invalidates signature.
- **Forgery**: Attackers without the key cannot generate valid requests.

## 2. Replay Protection
To prevent replay attacks (capturing valid requests and re-sending them), we implement:
- **Timestamp Validation**: `X-Timestamp` header must be within `+/- 60 seconds` of server time.
- **Sequence Numbers**: `X-Sequence` header must be strictly increasing per Sensor ID.

## 3. Transport Security (TLS)
- **Requirement**: In production, all traffic MUST use HTTPS (TLS 1.2+).
- **mTLS**: Optional Mutual TLS for sensor authentication in high-security deployments.
- **Certificate Pinning**: Sensors can be configured to pin the controller's certificate hash.

## 4. API Authentication
- **Bearer Tokens**: Sensors authenticate via JWT or Opaque Tokens in `Authorization` header.
- **Role-Based Access**: `SENSOR` role has write-only access to `/telemetry` and `/alerts`.
