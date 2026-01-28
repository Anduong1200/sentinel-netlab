# Runbook: Start/Stop Services

> Standard procedures for starting, stopping, and restarting Sentinel NetLab services

---

## Prerequisites

### Sensor Host

- [ ] Linux with monitor-mode WiFi adapter
- [ ] Python 3.9+ installed
- [ ] Root access or CAP_NET_RAW/CAP_NET_ADMIN
- [ ] `config.yaml` configured
- [ ] Network connectivity to controller

### Controller Host

- [ ] Docker and Docker Compose installed
- [ ] `ops/.env` configured (secrets set)
- [ ] TLS certificates in `ops/certs/`
- [ ] Ports 5000, 443, 5432, 6379 available

---

## Controller Operations

### Start Controller Stack

```bash
cd ops

# First time: configure environment
cp .env.example .env
# Edit .env - set all CHANGE_ME values!

# Generate TLS certs (dev only)
./scripts/generate-certs.sh ./certs

# Start all services
docker compose up -d

# Verify
docker compose ps
curl -f http://localhost:5000/api/v1/health
```

### Stop Controller

```bash
cd ops
docker compose down
```

### Restart Controller (Rolling)

```bash
cd ops
docker compose restart controller
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f controller
docker compose logs -f postgres --tail 100
```

### Health Check

```bash
# API health
curl -f http://localhost:5000/api/v1/health

# Database
docker compose exec postgres pg_isready -U sentinel

# Redis
docker compose exec redis redis-cli ping

# All services status
docker compose ps
```

---

## Sensor Operations

### Start Sensor (Manual)

```bash
cd /opt/sentinel-netlab

# Activate environment
source venv/bin/activate

# Enable monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up

# Start sensor
sudo python -m sensor.cli \
  --config config.yaml \
  --sensor-id sensor-01 \
  --iface wlan0
```

### Start Sensor (Systemd)

```bash
# Enable and start
sudo systemctl enable sentinel-sensor@wlan0
sudo systemctl start sentinel-sensor@wlan0

# Check status
sudo systemctl status sentinel-sensor@wlan0
```

### Stop Sensor

```bash
# Manual
Ctrl+C or kill the process

# Systemd
sudo systemctl stop sentinel-sensor@wlan0
```

### Sensor Health Check

```bash
# If metrics enabled
curl -f http://localhost:9100/metrics | grep sentinel_frames

# Check log
tail -f /var/log/sentinel/sensor.log

# Verify interface
iw wlan0 info | grep type  # Should show "monitor"
```

---

## Mock Mode (Development/CI)

### Start in Mock Mode

```bash
# No WiFi adapter needed
python -m sensor.cli \
  --config config.yaml \
  --sensor-id mock-sensor \
  --mock-mode
```

### Docker Mock Sensor

```bash
cd ops
docker compose --profile testing up -d mock-sensor
```

---

## Upgrade Procedure

### Controller Upgrade

```bash
cd ops

# Pull latest
git pull origin main

# Rebuild images
docker compose build --no-cache controller

# Rolling restart
docker compose up -d controller

# Verify
curl -f http://localhost:5000/api/v1/health
```

### Sensor Upgrade

```bash
cd /opt/sentinel-netlab

# Stop sensor
sudo systemctl stop sentinel-sensor@wlan0

# Pull latest
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run migrations if needed
# (check CHANGELOG for migration notes)

# Start sensor
sudo systemctl start sentinel-sensor@wlan0
```

---

## Rollback Procedure

### Controller Rollback

```bash
cd ops

# Check current version
docker compose exec controller cat /app/VERSION

# Stop current
docker compose down

# Checkout previous version
git checkout v1.0.0  # or previous tag

# Rebuild and start
docker compose build controller
docker compose up -d
```

### Database Rollback (Alembic)

```bash
# List migrations
docker compose exec controller alembic history

# Rollback one version
docker compose exec controller alembic downgrade -1

# Rollback to specific revision
docker compose exec controller alembic downgrade abc123
```

---

## Backup Procedures

### Database Backup

```bash
# Manual backup
docker compose exec postgres pg_dump -U sentinel sentinel > backup_$(date +%Y%m%d).sql

# Compressed
docker compose exec postgres pg_dump -U sentinel sentinel | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore Database

```bash
# Stop controller first
docker compose stop controller

# Restore
docker compose exec -T postgres psql -U sentinel sentinel < backup.sql

# Start controller
docker compose start controller
```

---

## Troubleshooting Quick Reference

| Symptom | Check | Fix |
|---------|-------|-----|
| Controller 502 | `docker compose logs nginx` | Restart controller |
| No frames captured | `iw wlan0 info` | Re-enable monitor mode |
| High latency | `docker compose logs controller` | Check DB connections |
| Disk full | `docker system df` | `docker system prune` |
| Auth failed | Check token in .env | Regenerate token |

---

## Emergency Contacts

- **On-call**: [Define escalation path]
- **Security issues**: security@example.com
- **Slack channel**: #sentinel-ops

---

*Last Updated: 2026-01-28*
