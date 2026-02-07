# Production Deployment Guide

> **Scope**: "Pilot" or "Small Production" deployment.
> **Assumptions**: You own or have authorization for the network. Strict security is enforced.

---

## 1. Reference Architecture

For production, we enforce a **Zero-Trust Network Architecture**:

*   **Public Zone** (`0.0.0.0:443`): **Reverse Proxy ONLY** (Nginx/Traefik).
*   **Private Zone** (Internal Docker Network):
    *   **Controller**: API & Ingestion Logic.
    *   **Database**: PostgreSQL + TimescaleDB (Persistent Data).
    *   **Redis**: Job Queue & Cache.
    *   **Worker**: Async Task Processing (Ingest/Alerts).

### Network Rules
1.  **NO direct database exposure**. Port 5432 must NOT be bound to host.
2.  **NO direct Redis exposure**. Port 6379 must NOT be bound to host.
3.  **TLS Termination** happens at the Reverse Proxy.
4.  **HSTS** is mandatory.

---

## 2. Secrets & Configuration (Fail-Fast)

Production will **crash immediately** if default secrets or insecure configs are detected.

### Required Environment Variables (`.env.prod`)

| Service | Variable | Purpose |
| :--- | :--- | :--- |
| **Global** | `SENTINEL_ENV=prod` | Enforces production mode settings. |
| **Controller** | `CONTROLLER_SECRET_KEY` | Flask session signing (64-char hex). |
| | `CONTROLLER_HMAC_SECRET` | Sensor data signing key (64-char hex). |
| | `API_AUTH_TOKEN` | Admin API access token. |
| | `DATABASE_URL` | Postgres connection string. |
| | `REDIS_URL` | Redis connection string. |
| | `TRUSTED_PROXY_CIDRS` | List of trusted proxy IPs (e.g., `172.16.0.0/12`). |
| **Dashboard** | `DASH_PASSWORD` | Access password (No default allowed). |
| **Postgres** | `POSTGRES_PASSWORD` | Database password. |

> [!CAUTION]
> **NEVER** commit `.env.prod` to version control. Use a secrets manager or secure injection.

---

## 3. Deployment Profile

### Production (Canonical)
*   **File**: `ops/docker-compose.prod.yml`
*   **Ports**: Exposes **only** 80/443 (via Nginx).
*   **Security**: Internal services (DB, Redis, MinIO, Controller) are isolated in the `sentinel-net` network with NO host port bindings.
*   **Secrets**: Requires `.env` with strong keys (fails fast if missing).

### Development / Debug (NOT for Production)
*   **File**: `ops/docker-compose.dev.yml`
*   **Ports**: Exposes DB (5432), Redis (6379), Controller (5000) for debugging.
*   **Security**: Relaxed. **DO NOT deploy this to the public internet.**

### Step-by-Step Deploy

1.  **Prepare Secrets**:
    ```bash
    # Copy strict template
    cp ops/.env.prod.example .env
    
    # Generate strong keys and fill .env
    openssl rand -hex 32
    nano .env
    ```

2.  **Pull Images**:
    ```bash
    docker compose -f ops/docker-compose.prod.yml pull
    ```

3.  **Run Database Migrations** (Crucial - do not skip):
    ```bash
    # Start DB first
    docker compose -f ops/docker-compose.prod.yml up -d postgres
    sleep 5

    # Run Alembic migrations
    docker compose -f ops/docker-compose.prod.yml run --rm controller alembic upgrade head
    ```

4.  **Start Full Stack**:
    ```bash
    docker compose -f ops/docker-compose.prod.yml up -d
    ```

---

## 4. Trusted Proxy & TLS

Because the Controller sits behind a proxy, it must know *which* proxy to trust for IP resolution.

### Nginx Configuration (Example)

```nginx
server {
    listen 443 ssl;
    # ... certs ...

    location / {
        proxy_pass http://controller:5000;
        
        # Mandatory Headers
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

### Controller Config
Set `TRUSTED_PROXY_CIDRS` to match your Docker network subnet (often `172.16.0.0/12` or `10.0.0.0/8` depending on setup).

---

## 5. Data Lifecycle & Maintenance

### Retention Policy
Disk usage can grow rapidly with high-frequency telemetry.
*   **Telemetry**: Defaults to 30 days (`TELEMETRY_RETENTION_DAYS`).
*   **PCAPs**: Manual cleanup required (or cron job).

### Backup Strategy
*   **Database**: Daily `pg_dump`.
    ```bash
    docker exec sentinel-prod-postgres pg_dump -U postgres sentinel > backup_$(date +%F).sql
    ```
*   **Restore**:
    ```bash
    cat backup.sql | docker exec -i sentinel-prod-postgres psql -U postgres sentinel
    ```

### Upgrades
1.  Update `docker-compose.prod.yml` image tags.
2.  `docker compose pull`.
3.  `docker compose up -d` (Recreates containers).
4.  Run migrations again (Idempotent).

---

## 🔗 Related Documentation
*   [Configuration Reference](../reference/config.md)
*   [Database Schema](../reference/schema.md)
*   [Operations Runbook](ops-runbook.md)
