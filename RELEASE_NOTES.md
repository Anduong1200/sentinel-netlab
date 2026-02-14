# Release Notes — v0.4.0 (2026-02-14)

**Sentinel NetLab v0.4.0** completes a comprehensive 5-pass release audit, fixes 45 bugs, and delivers a refactored dashboard and scalability improvements.

## 🚀 Highlights

### 1. Release Audit — 45 Bugs Fixed
Five systematic audit passes across 130+ production Python files:
-   **5 Critical Operational Bugs**: Capture thread death, alert data loss pipeline, schema rejection at API boundary
-   **Datetime Hygiene**: All timestamp generation now uses timezone-aware `datetime.now(UTC)`
-   **Logger Hygiene**: Removed all `logging.basicConfig()` calls from library modules (prevents root logger hijacking)
-   **Deprecated API**: Replaced `datetime.utcfromtimestamp()` with `datetime.fromtimestamp(tz=UTC)`
-   **Verification**: `ruff check`, `pytest` — all green

### 2. Dashboard Refactor
-   Refactored monolithic `app.py` into Dash Multi-Page App architecture
-   Pages: **Overview**, **Map**, **Threats**, **Signals**
-   Components: **Sidebar**, **Cards**

### 3. Hardened Security Architecture
-   **Trusted Proxy Model**: Explicit IP attribution/spoofing protection via `TRUSTED_PROXY_CIDRS`
-   **Strict TLS & HMAC**: Enforced HTTPS and Request Signing (`REQUIRE_TLS`, `REQUIRE_HMAC`)
-   **Fail-Fast Config**: Startup aborts immediately if secrets are missing or weak
-   **Least Privilege**: Non-root containers, read-only volumes where possible
-   **CI Security**: Trivy vulnerability fixes in Docker image layers

### 4. Observability Stack
-   **Structured Logging**: JSON logs with PII redaction (SSID, Tokens)
-   **Metrics**: Standardized Prometheus metrics (`ingest_*`, `queue_*`, `worker_*`)
-   **Correlation**: Distributed tracing via `X-Request-ID` and `X-Batch-ID`
-   **Dashboards**: Grafana ready (Ingest Health, Queue Lag)

### 5. Scalability
-   Database indexing and partitioning strategies
-   Bulk ingest endpoint for high-throughput sensor deployments
-   Background worker queue infrastructure

## 🛠 Upgrade Notes

### From v0.3.x
-   **No breaking changes** — all fixes are backward-compatible
-   All `logging.basicConfig` removals may affect standalone script usage — configure logging in your entry point

### From Beta/Dev
-   **Config Change**: `.env` structure has changed. Use `.env.example` as a reference
-   **Database**: Run `docker compose up migration` to align schema

## 📝 Configuration Checklist
1.  Generate Secrets: `openssl rand -hex 32` for `CONTROLLER_SECRET_KEY` etc.
2.  Set `TRUSTED_PROXY_CIDRS` if behind a Load Balancer
3.  Set `SENTINEL_LAB_MODE=true` only for isolated research environments

## 📚 Documentation
-   [Deployment Guide](docs/prod/deployment.md)
-   [Observability Contract](docs/reference/observability.md)
-   [Configuration Reference](docs/reference/config.md)
