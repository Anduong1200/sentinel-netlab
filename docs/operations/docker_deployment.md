# Docker Deployment Guide

> Complete guide for deploying Sentinel NetLab using Docker

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab/ops

# 2. Configure environment
cp .env.example .env
# Edit .env - set all CHANGE_ME values!

# 3. Generate certificates (dev only)
./scripts/generate-certs.sh ./certs

# 4. Start all services
docker compose up -d

# 5. Verify
curl http://localhost:5000/api/v1/health
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
│                                                                 │
│  ┌─────────┐  ┌────────────┐  ┌───────┐  ┌───────┐            │
│  │  Nginx  │──│ Controller │──│Postgres│──│ Redis │            │
│  │  :443   │  │   :5000    │  │ :5432  │  │:6379  │            │
│  └─────────┘  └────────────┘  └───────┘  └───────┘            │
│       │              │                                          │
│       │       ┌──────┴──────┐                                  │
│       │       │             │                                  │
│  ┌────┴────┐ ┌┴────────┐ ┌──┴──────┐                          │
│  │ Grafana │ │ MinIO   │ │Prometheus│                          │
│  │ :3000   │ │:9000/01 │ │  :9090   │                          │
│  └─────────┘ └─────────┘ └──────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Services

| Service | Port | Purpose |
|---------|------|---------|
| **nginx** | 80, 443 | Reverse proxy, TLS termination |
| **controller** | 5000 | REST API |
| **postgres** | 5432 | Database (TimescaleDB) |
| **redis** | 6379 | Cache, rate limiting |
| **minio** | 9000, 9001 | Object storage (PCAPs) |
| **prometheus** | 9090 | Metrics |
| **grafana** | 3000 | Dashboards |
| **alertmanager** | 9093 | Alert routing |

---

## Configuration

### Required Secrets

Generate strong secrets:

```bash
# Generate 32-byte hex secrets
openssl rand -hex 32  # CONTROLLER_SECRET_KEY
openssl rand -hex 32  # CONTROLLER_HMAC_SECRET
openssl rand -hex 16  # POSTGRES_PASSWORD
openssl rand -hex 16  # MINIO_ROOT_PASSWORD
```

### Environment Variables

```bash
# .env file
CONTROLLER_SECRET_KEY=<generated>
CONTROLLER_HMAC_SECRET=<generated>
POSTGRES_PASSWORD=<generated>
MINIO_ROOT_PASSWORD=<generated>
GRAFANA_ADMIN_PASSWORD=<generated>
```

---

## Commands

```bash
# Start all services
docker compose up -d

# Start with mock sensor (for testing)
docker compose --profile testing up -d

# View logs
docker compose logs -f controller
docker compose logs -f --tail 100

# Restart a service
docker compose restart controller

# Stop all
docker compose down

# Stop and remove volumes (DELETES DATA)
docker compose down -v

# Rebuild images
docker compose build --no-cache
docker compose up -d

# Scale (if needed)
docker compose up -d --scale controller=3
```

---

## Health Checks

```bash
# Controller
curl http://localhost:5000/api/v1/health

# Postgres
docker compose exec postgres pg_isready -U sentinel

# Redis
docker compose exec redis redis-cli ping

# MinIO
curl http://localhost:9000/minio/health/live
```

---

## TLS Setup

### Development (Self-Signed)

```bash
./scripts/generate-certs.sh ./certs
```

### Production (Let's Encrypt)

```bash
# Install certbot
apt install certbot

# Generate certificate
certbot certonly --standalone -d sentinel.example.com

# Copy to certs directory
cp /etc/letsencrypt/live/sentinel.example.com/fullchain.pem ./certs/server.crt
cp /etc/letsencrypt/live/sentinel.example.com/privkey.pem ./certs/server.key

# Restart nginx
docker compose restart nginx
```

### Auto-renewal

```bash
# Add to crontab
0 0 1 * * certbot renew && docker compose restart nginx
```

---

## Database Management

### Backup

```bash
# Manual backup
docker compose exec postgres pg_dump -U sentinel sentinel > backup_$(date +%Y%m%d).sql

# Automated backup (add to crontab)
0 2 * * * docker compose exec -T postgres pg_dump -U sentinel sentinel | gzip > /backups/sentinel_$(date +%Y%m%d).sql.gz
```

### Restore

```bash
docker compose exec -T postgres psql -U sentinel sentinel < backup.sql
```

### Migrations

```bash
docker compose exec controller alembic upgrade head
```

---

## Monitoring

### Grafana

1. Open http://localhost:3000
2. Login: admin / (GRAFANA_ADMIN_PASSWORD)
3. Dashboards pre-configured in `Sentinel NetLab` folder

### Prometheus

1. Open http://localhost:9090
2. Query: `sentinel_alerts_total`
3. Alert rules loaded from `alert_rules.yml`

### Alertmanager

1. Open http://localhost:9093
2. Configure receivers in `alertmanager.yml`

---

## Troubleshooting

| Issue | Check | Fix |
|-------|-------|-----|
| Controller won't start | `docker compose logs controller` | Check DATABASE_URL |
| Database connection failed | `docker compose ps postgres` | Wait for healthy state |
| Nginx 502 | `docker compose logs nginx` | Check controller is running |
| Out of disk | `docker system df` | `docker system prune` |
| Permission denied | File ownership | `chown -R 1000:1000 ./data` |

### View all container status

```bash
docker compose ps -a
```

### Container shell access

```bash
docker compose exec controller /bin/bash
docker compose exec postgres psql -U sentinel
docker compose exec redis redis-cli
```

---

## Production Checklist

- [ ] Change all default passwords in `.env`
- [ ] Generate proper TLS certificates
- [ ] Configure external backup storage
- [ ] Set up log aggregation
- [ ] Configure alertmanager receivers
- [ ] Enable REQUIRE_HMAC=true
- [ ] Review rate limits
- [ ] Set up monitoring alerts
- [ ] Document recovery procedures

---

*Last Updated: January 28, 2026*
