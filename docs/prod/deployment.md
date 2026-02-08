# Production Deployment Guide

## Overview
Sentinel NetLab follows a **Safe-by-Default** deployment architecture.
- **Fail-Fast**: Missing secrets or invalid configurations stop startup immediately.
- **Migration-First**: Database schemas must be fully migrated before the API accepts traffic.
- **Trusted Proxy**: `X-Forwarded-*` headers are only respected from explicitly configured IPs (`TRUSTED_PROXY_CIDRS`).

## Core Concepts

### 1. Trust Model & TLS
We enforce TLS via `X-Forwarded-Proto: https`. To prevent spoofing, this header is **only** accepted if the request originates from a trusted proxy (e.g., your Load Balancer or Nginx).
- **Configure**: Set `TRUSTED_PROXY_CIDRS` in `ops/.env`.
- **Verify**: The Controller logs `Access Log` with `ip` matching the real client IP.
- **See**: [Trusted Proxy Reference](../reference/proxy-trust.md)

### 2. Database Migrations (The "Migration Job")
We utilize a dedicated `migration` service (init container pattern) to handle schema changes.
- The `controller` and `worker` services will **wait** for the `migration` service to complete checks/upgrades.
- **Locking**: Alembic handles locking, ensuring multiple replicas do not race.
- **Source of Truth**: The `alembic_version` table is the definitive state. `db.create_all()` is **disabled**.

### 2. Readiness Gates
The Controller exposes a `/readyz` endpoint that checks:
- Database connectivity.
- Schema version matches code expectations.
- Critical tables (`telemetry`, `alerts`) exist.
If `/readyz` fails (503), the load balancer (or Nginx) will not route traffic to that instance.

## Deployment Steps

### Fresh Install
1. **Configure Secrets**:
   ```bash
   cp ops/.env.prod.example ops/.env
   # Edit ops/.env with strong passwords
   ```

2. **Start Stack**:
   ```bash
   docker compose -f ops/docker-compose.prod.yml up -d
   ```
   *The `migration` container will start, upgrade the DB, and exit. Controller will start after.*

### Upgrading Implementation (Code only)
1. Pull new images.
2. `docker compose -f ops/docker-compose.prod.yml up -d`
3. Containers recreate if image changed.

### Upgrading Schema (Adopting Existing DB)

#### Scenario A: Standard Upgrade
Just run `docker compose up -d`. The `migration` service applies pending changes automatically.

#### Scenario B: Adopting a "Wild" Database
If you have a database created by an older version (using `db.create_all()` without Alembic):
1. **Backup your data!**
2. Manually stamp the baseline:
   ```bash
   # Enter migration shell
   docker compose -f ops/docker-compose.prod.yml run --rm migration python -m alembic stamp 4085bd1d44e4
   ```
3. Run upgrade:
   ```bash
   docker compose -f ops/docker-compose.prod.yml up -d
   ```

#### Scenario C: Drift Detected
If `/readyz` returns 503 "Schema Drift":
1. Check logs: `docker compose logs migration`
2. If drift is minor, `alembic upgrade head` might fix it.
3. If critical conflict, manual SQL intervention is required.

## Troubleshooting

### Controller Stuck "Starting"
Check if `migration` service failed:
```bash
docker compose ps -a
docker compose logs migration
```
If migration failed, fix the DB issue, then restart.

### 503 Service Unavailable
The `/readyz` probe is failing. likely due to DB connectivity or schema mismatch.
Check `http://localhost/api/v1/health` (Liveness) vs `/readyz`.
