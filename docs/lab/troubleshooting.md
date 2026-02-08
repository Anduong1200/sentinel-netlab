# Lab Troubleshooting Guide

> **Scope**: Common issues in Lab Mode (`make lab-up`).
> **Goal**: Self-service resolution in < 5 minutes.

---

## ⚡ Quick Triage Checklist (2 Minutes)

Before diving deep, check the basics:

1.  **Is the stack actually running?**
    *   Run: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml ps`
    *   *Expected*: `sentinel-lab-proxy`, `controller`, `dashboard` are "Up" / "Healthy".
2.  **Are you using the Proxy URL?**
    *   Access: [http://localhost:8080](http://localhost:8080) (Everything goes through here).
    *   Do NOT try to access ports 5000 or 8050 directly.
3.  **Is Disk Space OK?**
    *   Run: `docker system df`
4.  **Is Docker Desktop Running?**
    *   Verify the whale icon is active.

---

## 🔧 Top 10 Common Issues

### 1. `make lab-up` runs but UI won't open
*   **Symptom**: "Connection Refused" or site can't be reached.
*   **Likely Cause**:
    *   Docker container exited immediately.
    *   Port 8050 is occupied by another app.
*   **Fix**:
    1.  Check status: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml ps`
    2.  If Dash container is `Exited`: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml logs dashboard`
    3.  If Port Conflict: Edit `.env.lab` to change `DASHBOARD_PORT=8051` or stop the conflicting app.
*   **Verify**: [http://localhost:8050](http://localhost:8050) loads.

### 2. Health Check Red / Controller Not Ready
*   **Symptom**: UI loads but shows no data. API `/health` returns error.
*   **Likely Cause**: Database initialization failed or containers are in a restart loop.
*   **Fix**:
    1.  Check logs: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml logs controller`
    2.  **Reset Lab**: `make lab-reset` (or `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml down -v` then restart).
*   **Verify**: `curl http://localhost:5000/api/v1/health` returns `{"ok": true}`.

### 3. "No Data / No Alerts" (Empty Dashboard)
*   **Symptom**: Dashboard is visible but empty.
*   **Likely Cause**:
    *   Seed script didn't run.
    *   Time drift causing ingest rejection.
*   **Fix**:
    1.  Run Seed: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml exec -T controller python ops/seed_lab_data.py`
    2.  Check Ingest Logs: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml logs controller | grep "Reject"`
*   **Verify**: Dashboard shows > 50 packets/alerts.

### 4. Permission Error (Capture/Hardware Mode)
*   **Symptom**: "Operation not permitted" or `wlan0mon` not found.
*   **Likely Cause**: You are trying to use real hardware without privileged mode, or on WSL2 (which often lacks WiFi support).
*   **Fix**:
    *   **Recommended**: Stick to **Mock Mode** (Offline first).
    *   If Hardware Required: Ensure you are on native Linux and read **[Safety Guide](safety.md)**.
*   **Verify**: Mock sensor runs without `sudo`.

### 5. Docker "No space left on device"
*   **Symptom**: Containers crash randomly; build fails.
*   **Likely Cause**: Old images/volumes filling disk.
*   **Fix**:
    *   `docker system prune -a` (Warning: deletes cached images).
    *   `docker volume prume`
*   **Verify**: `docker system df` shows free space.

### 6. Stale State / Weird Behavior after Reset
*   **Symptom**: You ran `lab-reset`, but old alerts are still there.
*   **Likely Cause**: Browser Cache or multiple Docker projects running (e.g., prod vs lab).
*   **Fix**:
    1.  Hard Refresh Browser (`Ctrl+F5`).
    2.  Ensure strict cleanup: `docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml down -v`
*   **Verify**: Dashboard is clean after reset.

### 7. Port Conflict (Bind Failed)
*   **Symptom**: Error `Bind for 0.0.0.0:5000 failed: port is already allocated`.
*   **Likely Cause**: Another instance of Sentinel or a different service (e.g., AirPlay listener) is using port 5000/8050.
*   **Fix**:
    1.  Find process: `netstat -ano | findstr :5000` (Win) or `lsof -i :5000` (Mac/Linux).
    2.  Kill process or change port in `.env.lab`.
*   **Verify**: `make lab-up` succeeds.

### 8. Time Drift / Clock Skew
*   **Symptom**: Logs show "Timestamp too old" or "Future timestamp". Ingest rejected.
*   **Likely Cause**: VM/WSL clock drifted from host time when suspended.
*   **Fix**:
    *   Sync System Clock.
    *   Restart Docker Desktop.
*   **Verify**: Ingest logs show `Accepted`.

### 9. Auth Failed / Invalid Signature
*   **Symptom**: Controller logs `401 Unauthorized` or `HMAC mismatch`.
*   **Likely Cause**: Sensor and Controller have different secrets (e.g., one container updated, one didn't).
*   **Fix**:
    *   `make lab-reset` (Forces regeneration of shared secrets).
*   **Verify**: Sensor logs show `Heartbeat OK`.

### 10. Performance Lag (UI Freezing)
*   **Symptom**: Dashboard is unresponsive.
*   **Likely Cause**: Too many points loaded in charts or limited Docker RAM (< 2GB).
*   **Fix**:
    *   Increase Docker RAM limit to 4GB.
    *   Run `make lab-reset` to wipe massive historical data.
*   **Verify**: UI loads in < 2 seconds.

---

## 🆘 Escalation: Collecting Diagnostics

If you still cannot resolve the issue, prepare the following information before opening a GitHub Issue.

### What to Collect (Safe)
1.  **Lab Logs**: `make lab-logs > lab_debug.log` (Attach last 200 lines).
2.  **Environment**: OS Version, Docker Version.
3.  **Command Run**: Exact command used (e.g., `make lab-up`).

> [!WARNING]
> **DO NOT** post your `.env.lab` file or `lab_debug.log` if it contains secrets or real PCAP data.
> **Redact** any IP addresses or tokens before sharing.
