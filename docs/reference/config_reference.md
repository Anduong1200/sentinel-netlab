# Configuration Reference

> **All environment variables for Sentinel NetLab.**

---

## Profile Selection

| Variable | Values | Default |
|----------|--------|---------|
| `SENTINEL_PROFILE` | `lab`, `prod` | `lab` |

---

## Controller

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `CONTROLLER_SECRET_KEY` | Flask secret key | Auto-generated | **Required** |
| `CONTROLLER_HOST` | Bind address | `0.0.0.0` | `0.0.0.0` |
| `CONTROLLER_PORT` | HTTP port | `5000` | `5000` |
| `CONTROLLER_DEBUG` | Debug mode | `true` | `false` |
| `DATABASE_URL` | SQLAlchemy URL | `sqlite:///lab.db` | `postgresql://...` |
| `TRUSTED_PROXY_COUNT` | Proxy hops | `0` | `1` |

---

## Database

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `POSTGRES_HOST` | Database host | N/A | `postgres` |
| `POSTGRES_PORT` | Database port | N/A | `5432` |
| `POSTGRES_DB` | Database name | N/A | `sentinel` |
| `POSTGRES_USER` | Database user | N/A | `postgres` |
| `POSTGRES_PASSWORD` | Database password | N/A | **Required** |
| `TELEMETRY_RETENTION_DAYS` | Telemetry TTL | `7` | `30` |
| `ALERT_RETENTION_DAYS` | Alert TTL | `30` | `365` |

---

## Redis

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `REDIS_HOST` | Redis host | `redis` | `redis` |
| `REDIS_PORT` | Redis port | `6379` | `6379` |
| `REDIS_PASSWORD` | Redis password | Auto-generated | **Required** |
| `REDIS_DB` | Redis database | `0` | `0` |

---

## Dashboard

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `DASH_HOST` | Bind address | `0.0.0.0` | `0.0.0.0` |
| `DASH_PORT` | HTTP port | `8050` | `8050` |
| `DASH_DEBUG` | Debug mode | `true` | `false` |
| `DASH_PASSWORD` | Admin password | Auto-generated | **Required** |
| `CONTROLLER_URL` | API endpoint | `http://controller:5000` | `http://controller:5000` |
| `DASHBOARD_API_TOKEN` | API auth token | Auto-generated | **Required** |

---

## Sensor

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `SENSOR_ID` | Unique identifier | `lab-sensor-01` | **Required** |
| `SENSOR_MOCK_MODE` | Use mock data | `true` | `false` |
| `SENSOR_AUTH_TOKEN` | Controller auth | Auto-generated | **Required** |
| `CONTROLLER_URL` | API endpoint | `http://controller:5000` | `https://sentinel.example.com/api` |
| `CAPTURE_INTERFACE` | WiFi interface | N/A | `wlan0mon` |
| `CAPTURE_CHANNELS` | Channels to scan | `1,6,11` | `1,6,11` |

---

## Worker

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `CELERY_BROKER_URL` | Redis URL | `redis://redis:6379/0` | `redis://:${REDIS_PASSWORD}@redis:6379/0` |
| `CELERY_RESULT_BACKEND` | Result store | Same as broker | Same as broker |
| `CELERY_CONCURRENCY` | Worker threads | `2` | `4` |

---

## Detection Algorithms

| Variable | Description | Default |
|----------|-------------|---------|
| `EVIL_TWIN_THRESHOLD` | Alert score threshold | `60` |
| `EVIL_TWIN_CONFIRMATION_WINDOW` | Seconds to confirm | `30` |
| `DEAUTH_THRESHOLD_PER_SEC` | Flood threshold | `10` |
| `DEAUTH_COOLDOWN_SECONDS` | Alert cooldown | `60` |

---

## Logging

| Variable | Description | Lab Default | Prod Default |
|----------|-------------|-------------|--------------|
| `LOG_LEVEL` | Minimum level | `DEBUG` | `INFO` |
| `LOG_FORMAT` | Output format | `console` | `json` |
| `LOG_FILE` | File path | None | `/var/log/sentinel/app.log` |

---

## Behavior by Profile

| Feature | `lab` | `prod` |
|---------|-------|--------|
| SQLite allowed | ✅ | ❌ |
| Mock sensor | ✅ | ❌ |
| Seed/Reset | ✅ | ❌ |
| Auto-gen secrets | ✅ | ❌ |
| TLS required | ❌ | ✅ |
| Debug mode | ✅ | ❌ |
