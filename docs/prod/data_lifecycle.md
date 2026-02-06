# Data Lifecycle

> **Retention, backup, and recovery for Sentinel NetLab.**

---

## Data Categories

| Category | Retention | Backup Frequency | Recovery Priority |
|----------|-----------|------------------|-------------------|
| Alerts | 1 year | Daily | High |
| Telemetry | 30 days | Weekly | Medium |
| Sensor metadata | Indefinite | Daily | High |
| Config/Secrets | N/A | On change | Critical |
| Logs | 7 days | None | Low |

---

## Retention Configuration

### Environment Variables

```bash
# .env
TELEMETRY_RETENTION_DAYS=30
ALERT_RETENTION_DAYS=365
LOG_RETENTION_DAYS=7
```

### TimescaleDB Compression

Telemetry is automatically compressed after 7 days:

```sql
-- View compression status
SELECT * FROM timescaledb_information.compressed_chunk_stats;
```

---

## Backup Procedures

### Database Backup

```bash
# Full backup
docker-compose exec postgres pg_dump -U postgres sentinel > backup_$(date +%Y%m%d).sql

# Compressed backup
docker-compose exec postgres pg_dump -U postgres -Fc sentinel > backup_$(date +%Y%m%d).dump
```

### Automated Backup Script

```bash
#!/bin/bash
# /opt/sentinel/backup.sh
set -e

BACKUP_DIR=/backups/sentinel
DATE=$(date +%Y%m%d_%H%M%S)

# Database
docker-compose -f /opt/sentinel/ops/docker-compose.prod.yml exec -T postgres \
    pg_dump -U postgres -Fc sentinel > ${BACKUP_DIR}/db_${DATE}.dump

# Secrets (encrypted)
gpg --encrypt --recipient backup@example.com \
    /opt/sentinel/.env > ${BACKUP_DIR}/env_${DATE}.gpg

# Cleanup old backups (keep 30 days)
find ${BACKUP_DIR} -name "*.dump" -mtime +30 -delete

echo "Backup completed: ${DATE}"
```

Add to cron:
```cron
0 1 * * * /opt/sentinel/backup.sh >> /var/log/sentinel-backup.log 2>&1
```

---

## Restore Procedures

### Database Restore

```bash
# Stop services
docker-compose down

# Restore from backup
docker-compose up -d postgres
docker-compose exec -T postgres psql -U postgres -c "DROP DATABASE IF EXISTS sentinel;"
docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE sentinel;"
docker-compose exec -T postgres pg_restore -U postgres -d sentinel < backup.dump

# Restart all services
docker-compose up -d
```

### Point-in-Time Recovery

If using WAL archiving:

```bash
# Restore to specific time
docker-compose exec postgres psql -U postgres -c "
SELECT pg_stop_backup();
"

# Update recovery.conf with target_time
# Restart postgres in recovery mode
```

---

## Disaster Recovery

### RTO/RPO Targets

| Scenario | RTO | RPO |
|----------|-----|-----|
| Database corruption | 1 hour | 24 hours |
| Server failure | 4 hours | 24 hours |
| DC failure | 8 hours | 24 hours |

### Recovery Checklist

1. [ ] Provision new infrastructure
2. [ ] Install Docker/Docker Compose
3. [ ] Clone repository
4. [ ] Restore `.env` from encrypted backup
5. [ ] Restore database from backup
6. [ ] Reconfigure sensor auth tokens
7. [ ] Verify health checks pass
8. [ ] Update DNS/load balancer

---

## Audit Log

Sensitive operations are logged:

| Event | Logged Fields |
|-------|---------------|
| Login | user, ip, timestamp, success |
| API access | token, endpoint, timestamp |
| Config change | user, field, old_value, new_value |
| Alert action | user, alert_id, action |

Query audit logs:
```sql
SELECT * FROM audit_log
WHERE timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;
```

---

## Storage Sizing

### Estimation Formula

```
Daily telemetry = sensors × frames_per_min × 60 × 24 × 200 bytes
Daily alerts = ~100 × 2 KB = 200 KB

Example:
- 10 sensors × 100 frames/min × 60 × 24 × 200 = 28.8 GB/day
- 30-day retention = ~865 GB
- With compression = ~100 GB
```

### Monitoring

```bash
# Current usage
docker-compose exec postgres psql -U postgres -d sentinel -c "
SELECT pg_size_pretty(pg_database_size('sentinel'));
"
```
