# Database Schema Reference

## Source of Truth
The canonical source of truth for the database schema is **Alembic Migrations** (`controller/migrations/versions`).
- **Do not** modify the database manually.
- **Do not** use `db.create_all()`.
- **Do not** rely solely on `models.py` (though it should match migrations via `alembic check`).

## Schema Overview

### Core Tables
| Table | Description | Criticality |
| :--- | :--- | :--- |
| `telemetry` | Time-series data from sensors. Hypertable in Postgres. | **Critical** |
| `alerts` | Detected threats and anomalies. | **Critical** |
| `sensors` | Registered sensor inventory and status. | **Critical** |
| `ingest_jobs` | Deduplication and idempotency tracking. | High |
| `api_tokens` | Authentication tokens for API access. | **Critical** |
| `audit_log` | Security audit trail. | High |

### Initial Setup
The `ops/init-db.sql` script is responsible **ONLY** for:
1. Creating the database (`sentinel`).
2. creating the role (`sentinel`).
3. Enabling extensions (`timescaledb`, `pg_stat_statements`).

It does **NOT** create tables. Tables are created by the `migration` job during deployment.

## Migration Strategy

### Development
1. Modify `controller/db/models.py`.
2. Generate migration: `alembic revision --autogenerate -m "description"`.
3. Review the generated file in `controller/migrations/versions/`.
4. Apply: `alembic upgrade head`.

### Production
Migrations are applied automatically by the `migration` service (init container) before the Controller starts.
- The `migration` service runs `alembic upgrade head`.
- The Controller waits for this service to complete.
- If migration fails, the deployment halts (Fail-Fast).

## Troubleshooting Drift
If `alembic check` reports drift or `/readyz` fails:
1. Ensure `CONTROLLER_DATABASE_URL` is correct.
2. Check if a manual change was made to the DB.
3. Use `alembic history` to see applied versions.
4. Use `alembic current` to see current version.
