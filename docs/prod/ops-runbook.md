# Operations Runbook

> **Goal**: Maintain availability, reliability, and data integrity.
> **Format**: Symptom -> Cause -> Immediate Fix -> Prevention.

---

## 1. Health Baseline ("What Good Looks Like")

Before fixing issues, know your baseline metrics:

| Metric | Healthy Range | Critical Threshold |
| :--- | :--- | :--- |
| **Ingest Success** | > 99.5% | < 95% (Drop Rate Spike) |
| **Queue Lag** | < 500 msgs | > 5,000 msgs |
| **Heartbeat Age** | < 2 mins | > 5 mins (Stale Sensor) |
| **Disk Usage** | < 70% | > 90% (Risk of Crash) |
| **DB Connections** | < 50 | > 90 (Saturation) |

---

## 2. Top 10 Incidents

### 1. High Queue Lag (Backlog Growth)
*   **Symptom**: Dashboard alerts are delayed (minutes behind real-time). Redis memory usage high.
*   **Likely Cause**: Ingest rate > Worker capacity, or Worker crashed.
*   **Immediate Action**:
    1.  Check worker status: `docker compose ps worker`
    2.  Scale workers temporarily: `docker compose up -d --scale worker=4`
*   **Prevention**: Tune `BATCH_SIZE` or add dedicated ingest nodes.

### 2. Ingest 500 Errors / Drop Rate Spike
*   **Symptom**: Sensors report non-200 responses. `ingest_success_rate` drops.
*   **Likely Cause**: Database constraint violation, Schema mismatch, or Bug.
*   **Immediate Action**:
    1.  Check Controller logs for tracebacks: `docker logs sentinel-prod-controller --tail 200`
    2.  If DB error: Check migrations (`alembic current`).
*   **Prevention**: Semantic validation in API before DB write.

### 3. Stale Sensors (Heartbeat Missing)
*   **Symptom**: "Online Sensors" count drops. Sensors marked "Offline".
*   **Likely Cause**: Network partition, Sensor power loss, or Auth token rotated.
*   **Immediate Action**:
    1.  Ping sensor from controller.
    2.  Check sensor local logs (`journalctl -u sentinel-sensor`).
*   **Prevention**: Monitor `last_seen` metric.

### 4. Disk Pressure (No Space Left)
*   **Symptom**: PostgreSQL panic, Docker containers crashing.
*   **Likely Cause**: Telemetry retention too long, or un-rotated logs.
*   **Immediate Action**:
    1.  Prune Docker: `docker system prune -a` (Careful!)
    2.  Vacuum DB: `VACUUM FULL telemetry_frames` (Maintenance window needed).
*   **Prevention**: Enforce valid `TELEMETRY_RETENTION_DAYS`. Use external volumes.

### 5. DB Connection Saturation
*   **Symptom**: `FATAL: remaining connection slots are reserved...`.
*   **Likely Cause**: Connection leak in app, or too many workers.
*   **Immediate Action**:
    1.  Restart Controller/Worker to release pool.
    2.  Reduce `SQLALCHEMY_POOL_SIZE`.
*   **Prevention**: Use PgBouncer for pooling.

### 6. Auth Failures (401/HMAC)
*   **Symptom**: Ingest rejected with 401. Log: `Signature mismatch`.
*   **Likely Cause**: `CONTROLLER_HMAC_SECRET` mismatch between Sensor and Controller.
*   **Immediate Action**:
    1.  Verify secrets in `.env.prod`.
    2.  Redeploy sensor with correct secret.
*   **Prevention**: Configuration Management (Ansible/Chef).

### 7. Alert Spam (Alert Fatigue)
*   **Symptom**: 1000s of "Deauth Detected" in 1 minute.
*   **Likely Cause**: Detector threshold too sensitive or legit Pen-Test.
*   **Immediate Action**:
    1.  Silence Alert rule temporarily.
    2.  Increase `dedup_window` in detector config.
*   **Prevention**: Tuning phase baseline.

### 8. TLS/Proxy Misconfiguration
*   **Symptom**: Mixed Content errors, 502 Bad Gateway.
*   **Likely Cause**: Nginx upstream down or Cert expired.
*   **Immediate Action**:
    1.  Check Nginx logs.
    2.  Renew Certbot: `certbot renew`.
*   **Prevention**: Auto-renewal cron.

### 9. Report Generation Failure
*   **Symptom**: PDF export spins forever or 504 Gateway Timeout.
*   **Likely Cause**: Query too expensive (scanning full table).
*   **Immediate Action**:
    1.  Narrow time range (Last 1 hour vs Last 7 days).
    2.  Check DB CPU usage.
*   **Prevention**: Pre-calculated summary tables (Materialized Views).

### 10. Time Drift (Ingest Rejection)
*   **Symptom**: Data rejected as "Too Old" or "Future".
*   **Likely Cause**: NTP failure on Sensor.
*   **Immediate Action**:
    1.  Force NTP sync on sensor: `chronyc -a makestep`.
*   **Prevention**: Monitor `drift_seconds` metric.

---

## 3. Diagnostics Bundle

When escalating to L3/Engineering, collect:

1.  **Compose Status**: `docker compose ps`
2.  **Resource Usage**: `docker stats --no-stream`
3.  **Logs (Redacted)**:
    ```bash
    # Extract last 500 lines, removing potential tokens
    docker compose logs --tail 500 | sed -E 's/Bearer [a-zA-Z0-9.\-_]+/Bearer [REDACTED]/g' > incident.log
    ```

> [!WARNING]
> **Data Privacy**: Ensure no PCAP data containing PII (MACs/SSIDs) is shared externally unless authorized.
