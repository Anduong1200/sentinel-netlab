# Configuration Reference

This guide details all environment variables used by Sentinel NetLab for both **Production** and **Lab** modes.

## 1. Quick Start (Token Generation)

You **MUST** generate secure secrets for production. Do not use default values.

```bash
# Generate 32-byte hex for SECRET_KEY and PASSWORDS
openssl rand -hex 32

# Generate 16-byte hex for HMAC_SECRET
openssl rand -hex 16
```

## 2. Environment Variables

### Core (Production)
| Variable | Required | Description | Example |
| :--- | :---: | :--- | :--- |
| `CONTROLLER_SECRET_KEY` | ✅ | Flask Session Secret (32 bytes hex) | `a1b2...` |
| `CONTROLLER_HMAC_SECRET` | ✅ | Shared secret for Sensor signatures (16 bytes hex) | `c3d4...` |
| `POSTGRES_PASSWORD` | ✅ | Database password | `StrongPass!` |
| `REDIS_PASSWORD` | ✅ | Redis password | `RedisPass!` |
| `MINIO_ROOT_PASSWORD` | ✅ | Object Storage admin password | `MinioPass!` |
| `GRAFANA_ADMIN_PASSWORD` | ✅ | Dashboard admin password | `GrafanaPass!` |

### Security & Tuning
| Variable | Default | Description |
| :--- | :--- | :--- |
| `REQUIRE_TLS` | `true` | Enforce HTTPS (Incoming). |
| `REQUIRE_HMAC` | `true` | Enforce Request Signing. |
| `MAX_TIME_DRIFT_SECONDS` | `300` | Max allowed timestamp drift. |
| `RATE_LIMIT_DEFAULT` | `100 per minute` | Global API rate limit. |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1` | Trusted proxies for IP attribution. |

### Lab Mode (Attack Simulation)
| Variable | Required | Description |
| :--- | :---: | :--- |
| `SENTINEL_LAB_MODE` | ⚠️ | Set to `true` to enable attack simulators. |
| `LAB_API_KEY` | ⚠️ | API Key for Lab Control interface. |
| `WIFI_INTERFACE` | - | Interface for injection (e.g., `wlan0Mon`). |

## 3. Deployment Files

*   **`.env.prod`**: Production secrets. **NEVER COMMIT**.
*   **`.env.lab`**: Lab simulation settings.
*   **`.env.example`**: Template for all settings.

## 4. Feature Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `ENABLE_ROLLING_PCAP` | `false` | Enable continuous packet capture. |
| `ENABLE_DEBUG_LOGS` | `false` | Verbose logging (JSON format). |
