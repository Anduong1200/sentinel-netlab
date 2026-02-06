# Operations Runbook

> **Day-to-day operations for Sentinel NetLab in production.**

---

## Health Checks

### Quick Status

```bash
# All services healthy?
docker-compose -f ops/docker-compose.prod.yml ps

# Controller health
curl -s https://sentinel.example.com/api/v1/health | jq

# Dashboard health
curl -s https://sentinel.example.com/ -o /dev/null -w "%{http_code}"
```

### Expected Output

| Service | Healthy State |
|---------|---------------|
| controller | HTTP 200, `{"status": "healthy"}` |
| dashboard | HTTP 200 |
| postgres | `pg_isready` returns 0 |
| redis | `redis-cli ping` returns PONG |
| worker | Celery heartbeat active |

---

## Common Issues

### 1. Queue Lag High

**Symptom**: Alerts delayed, dashboard shows stale data

**Diagnosis**:
```bash
# Check queue depth
docker-compose exec redis redis-cli LLEN celery

# Check worker status
docker-compose logs worker --tail 100
```

**Resolution**:
```bash
# Scale workers
docker-compose up -d --scale worker=3

# Or restart stuck worker
docker-compose restart worker
```

---

### 2. Sensor Not Reporting

**Symptom**: Sensor shows "stale" in dashboard

**Diagnosis**:
```bash
# Check sensor logs
docker-compose logs sensor --tail 100

# Verify network connectivity
docker-compose exec sensor curl -s http://controller:5000/api/v1/health
```

**Resolution**:
| Issue | Fix |
|-------|-----|
| Auth failed | Verify `SENSOR_AUTH_TOKEN` matches |
| Network error | Check DNS, firewall rules |
| Crash loop | Check sensor logs for hardware errors |

---

### 3. Database Full

**Symptom**: Ingestion fails, "disk full" errors

**Diagnosis**:
```bash
# Check table sizes
docker-compose exec postgres psql -U postgres -d sentinel -c "
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
"
```

**Resolution**:
```bash
# Run retention job manually
docker-compose exec controller python -m scripts.retention --days 30

# Or increase storage
# Then update TELEMETRY_RETENTION_DAYS in .env
```

---

### 4. High Memory Usage

**Symptom**: OOM kills, slow response

**Diagnosis**:
```bash
docker stats --no-stream
```

**Resolution**:
```yaml
# docker-compose.prod.yml - add memory limits
services:
  controller:
    deploy:
      resources:
        limits:
          memory: 2G
```

---

## Scheduled Tasks

| Task | Schedule | Purpose |
|------|----------|---------|
| Retention cleanup | Daily 02:00 | Remove old telemetry |
| Database vacuum | Weekly Sun 03:00 | Reclaim space |
| Health check | Every 5 min | Alert on failure |
| Backup | Daily 01:00 | Point-in-time recovery |

---

## Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Queue depth | > 1000 | > 10000 |
| Sensor staleness | > 5 min | > 15 min |
| API latency | > 500ms | > 2s |
| Disk usage | > 70% | > 90% |
| Memory usage | > 70% | > 90% |

---

## Escalation

| Level | Contact | When |
|-------|---------|------|
| L1 | On-call | Any alert |
| L2 | Platform team | Critical > 15 min |
| L3 | Security team | Suspected breach |

---

## Useful Commands

```bash
# View all logs
docker-compose logs -f --tail 100

# Enter controller shell
docker-compose exec controller /bin/bash

# Database query
docker-compose exec postgres psql -U postgres -d sentinel

# Clear Redis queue (CAUTION)
docker-compose exec redis redis-cli FLUSHDB

# Force detector refresh
docker-compose exec controller python -c "from algos import reload_all; reload_all()"
```
