# Release Notes - v1.0.0 (Production Ready)

**Sentinel NetLab v1.0.0** marks the first production-ready release, featuring a hardened architecture, complete observability stack, and robust security controls.

## 🚀 Key Features

### 1. Hardened Security Architecture
-   **Trusted Proxy Model**: Explicit IP attribution/spoofing protection via `TRUSTED_PROXY_CIDRS`.
-   **Strict TLS & HMAC**: Enforced HTTPS and Request Signing (`REQUIRE_TLS`, `REQUIRE_HMAC`).
-   **Fail-Fast Config**: Startup aborts immediately if secrets are missing or weak.
-   **Least Privilege**: Non-root containers, read-only volumes where possible.

### 2. Observability Stack (Ship-Ready)
-   **Structured Logging**: JSON logs with PII redaction (SSID, Tokens).
-   **Metrics**: Standardized Prometheus metrics (`ingest_*`, `queue_*`, `worker_*`).
-   **Correlation**: Distributed tracing via `X-Request-ID` and `X-Batch-ID`.
-   **Dashboards**: Grafana ready (Ingest Health, Queue Lag).

### 3. Data Integrity & Migrations
-   **Migration-First**: `migration` init container guarantees schema consistency before app start.
-   **Canonical Schema**: Alembic is the single source of truth.
-   **Safe Lab Mode**: Isolated attack simulation features (disabled by default).

### 4. Developer Experience
-   **Unified Config**: Single `.env.example` for Lab/Prod.
-   **Documentation**: Comprehensive guides for Deployment, Ops, and Lab.
-   **CI/CD**: Guardrails for Observability and Security.

## 🛠 Upgrade Notes

### From Beta/Dev
-   **Config Change**: `.env` structure has changed. Use `.env.example` as a reference.
-   **Database**: Run `docker compose up migration` to align schema.

## 📝 Configuration Checklist
1.  Generate Secrets: `openssl rand -hex 32` for `CONTROLLER_SECRET_KEY` etc.
2.  Set `TRUSTED_PROXY_CIDRS` if behind a Load Balancer.
3.  Set `SENTINEL_LAB_MODE=true` only for isolated research environments.

## 📚 Documentation
-   [Deployment Guide](docs/prod/deployment.md)
-   [Observability Contract](docs/reference/observability.md)
-   [Configuration Reference](docs/reference/config.md)
