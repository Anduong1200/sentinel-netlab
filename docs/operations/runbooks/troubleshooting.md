# Troubleshooting Runbook

## 1. Controller Won't Start (Exit Code 1)
**Symptom**: Container exits immediately with `RuntimeError`.

**Cause**: Missing strict production secrets.

**Fix**:
Check logs:
```bash
docker logs sentinel-controller
```
If you see `CRITICAL: Missing required production secrets`, you must set:
- `CONTROLLER_SECRET_KEY`
- `CONTROLLER_HMAC_SECRET`
- `CONTROLLER_DATABASE_URL`

For local dev, set `ENVIRONMENT=development` to bypass headers (defaults to insecure secrets).

## 2. Sensor "Unauthorized" (401)
**Symptom**: Sensor logs `HTTP 401` or `Invalid signature`.

**Cause**:
1. Token mismatch.
2. HMAC Secret mismatch (if signature enabled).
3. Time drift > 5 minutes.

**Fix**:
1. Verify `SENSOR_AUTH_TOKEN` matches database.
2. Verify `SENSOR_HMAC_SECRET` is identical on Sensor and Controller.
3. Check time sync:
   ```bash
   date -u
   # vs
   curl https://controller/api/v1/time
   ```

## 3. Rotating Secrets (Zero Downtime)
**Scenario**: You suspect a leak of `CONTROLLER_HMAC_SECRET`.

**Procedure**:
1.  **Generate New Secret**: `openssl rand -hex 32`
2.  **Deploy to Controller**:
    *   Update `CONTROLLER_HMAC_SECRET` in deployment.
    *   *Note*: Ideally, support dual-key verification (current + previous) in code. (Currently requires maintenance window).
3.  **Deploy to Sensors**: 
    *   Update `SENSOR_HMAC_SECRET` on all sensors.
    *   Restart sensors.
4.  **Verify**: Check dashboard for incoming heartbeat.
