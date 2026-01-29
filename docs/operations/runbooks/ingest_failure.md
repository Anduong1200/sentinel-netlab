# Incident Playbook: Ingest Failure

> Procedure for diagnosing and resolving data ingest failures

> [!WARNING]
> WORK IN PROGRESS: Some steps reference `postgres` or `admin/flush-queue` endpoints which may not be fully wired in the current stable release. Verify components exist before running commands.

---

## Symptoms

- No new data appearing in controller
- `sentinel_frames_captured_total` counter stopped increasing
- Alerts about sensor connectivity
- Dashboard showing stale data

---

## Severity Assessment

| Impact | Severity | Response Time |
|--------|----------|---------------|
| Single sensor offline | Medium | 1 hour |
| Multiple sensors offline | High | 30 minutes |
| All sensors offline | Critical | 15 minutes |
| Controller unreachable | Critical | 15 minutes |

---

## Diagnostic Steps

### Step 1: Identify Scope

```bash
# Check which sensors are affected
curl -s http://controller:5000/api/v1/sensors | jq '.sensors[] | {id, status, last_seen}'

# Check Prometheus for sensor heartbeats
# Query: sentinel_sensor_uptime_seconds
```

**Decision Point:**
- Single sensor → Go to Step 2A (Sensor-side)
- All sensors → Go to Step 2B (Controller-side)

---

### Step 2A: Sensor-Side Diagnosis

**On the affected sensor host:**

```bash
# 1. Check service status
sudo systemctl status sentinel-sensor@wlan0

# 2. Check logs for errors
sudo journalctl -u sentinel-sensor@wlan0 --since "10 minutes ago"

# 3. Check network interface
ip link show wlan0
iw wlan0 info  # Should show type: monitor

# 4. Check network connectivity
ping controller.example.com
curl -v https://controller.example.com/api/v1/health

# 5. Check disk space
df -h /var/log

# 6. Check CPU/memory
top -bn1 | head -20
```

**Common Issues:**

| Finding | Cause | Fix |
|---------|-------|-----|
| Service not running | Crashed | Restart service |
| Interface not in monitor | Driver reset | Re-enable monitor mode |
| Connection refused | Network issue | Check firewall/routing |
| Disk full | Log bloat | Clear old logs |
| High CPU | Burst traffic | Check for attack/tune |

---

### Step 2B: Controller-Side Diagnosis

**On the controller host:**

```bash
# 1. Check all services
cd ops && docker compose ps

# 2. Check controller logs
docker compose logs --tail 100 controller

# 3. Check database connectivity
docker compose exec postgres pg_isready -U sentinel

# 4. Check Redis
docker compose exec redis redis-cli ping

# 5. Check ingest metrics
curl -s http://localhost:5000/metrics | grep ingest

# 6. Check disk space
docker system df
df -h /var/lib/docker
```

**Common Issues:**

| Finding | Cause | Fix |
|---------|-------|-----|
| Controller not running | Crash | `docker compose restart controller` |
| Database down | Resource exhaustion | Restart postgres |
| Connection pool exhausted | Too many connections | Increase pool size |
| High latency | Heavy load | Scale or tune |

---

### Step 3: Network Diagnosis

```bash
# From sensor to controller
traceroute controller.example.com
curl -v --connect-timeout 5 https://controller.example.com/api/v1/health

# Check TLS
openssl s_client -connect controller.example.com:443 </dev/null

# Check DNS
nslookup controller.example.com
```

---

## Resolution Actions

### Restart Sensor

```bash
# Graceful restart
sudo systemctl restart sentinel-sensor@wlan0

# If interface issue
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
sudo systemctl restart sentinel-sensor@wlan0
```

### Restart Controller

```bash
cd ops
docker compose restart controller

# If database issue
docker compose restart postgres
docker compose restart controller
```

### Clear Backlog

After extended outage, sensors may have queued data:

```bash
# Check queue size on sensor
ls -la /var/lib/sentinel/queue/

# Force flush (if stuck)
curl -X POST http://localhost:9100/admin/flush-queue
```

### Database Recovery

```bash
# Check for locks
docker compose exec postgres psql -U sentinel -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# Kill stuck queries
docker compose exec postgres psql -U sentinel -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'active' AND query_start < now() - interval '5 minutes';"
```

---

## Verification

After resolution:

```bash
# 1. Confirm service health
curl -f http://controller:5000/api/v1/health

# 2. Check metrics recovering
curl -s http://localhost:5000/metrics | grep sentinel_frames

# 3. Verify data flow
# Watch: sentinel_frames_captured_total should increase

# 4. Check alerts cleared
# Alertmanager UI: http://localhost:9093
```

---

## Post-Incident

1. **Document** the incident in ticketing system
2. **Attach logs** from affected period
3. **Record** timeline of events
4. **Root cause** analysis if recurring
5. **Update** runbook if new failure mode

### Incident Report Template

```markdown
## Incident: Ingest Failure [DATE]

**Duration**: [Start Time] - [End Time]
**Severity**: [Critical/High/Medium/Low]
**Affected**: [Sensors/Data/Users]

### Timeline
- HH:MM - Alert fired
- HH:MM - Investigation started
- HH:MM - Root cause identified
- HH:MM - Fix applied
- HH:MM - Service restored

### Root Cause
[Description]

### Resolution
[Steps taken]

### Action Items
- [ ] Preventive measure 1
- [ ] Monitoring improvement
- [ ] Documentation update
```

---

## Escalation

| Level | Condition | Contact |
|-------|-----------|---------|
| L1 | Single sensor, < 1 hour | On-call engineer |
| L2 | Multiple sensors, > 1 hour | Senior engineer |
| L3 | All sensors, data loss | Engineering lead |

---

*Last Updated: 2026-01-28*
