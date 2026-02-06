# Production Deployment Guide

> **Deploy Sentinel NetLab for real-world wireless threat monitoring.**

---

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker | v20.10+ |
| Docker Compose | v2.x |
| RAM | 8 GB |
| Storage | 50 GB SSD |
| Network | Dedicated VLAN for sensors |

---

## Architecture Overview

```
                    ┌─────────────────────┐
                    │   Reverse Proxy     │
                    │   (Nginx/Traefik)   │
                    │   :443 (TLS)        │
                    └─────────┬───────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼───────┐     ┌───────▼───────┐     ┌───────▼───────┐
│   Dashboard   │     │  Controller   │     │    Grafana    │
│    :8050      │     │    :5000      │     │    :3000      │
└───────────────┘     └───────┬───────┘     └───────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼───────┐     ┌───────▼───────┐     ┌───────▼───────┐
│   Postgres    │     │    Redis      │     │    Worker     │
│  (Timescale)  │     │   (Queue)     │     │  (Celery)     │
└───────────────┘     └───────────────┘     └───────────────┘
```

---

## Step 1: Prepare Secrets

**Production requires explicit secrets - no defaults allowed.**

Create `.env` file (NOT `.env.lab`):

```bash
# Required - generate with: openssl rand -hex 32
CONTROLLER_SECRET_KEY=<64-char-hex>
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
API_AUTH_TOKEN=<64-char-hex>

# Required for sensors
SENSOR_AUTH_TOKEN=<64-char-hex>

# Required for dashboard
DASH_PASSWORD=<strong-password>
```

> ⚠️ **Never commit secrets to git.** Use a secrets manager in production.

---

## Step 2: Configure TLS

### Option A: Traefik (Recommended)

```yaml
# docker-compose.prod.yml - traefik service
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - "./letsencrypt:/letsencrypt"
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
```

### Option B: Nginx + Certbot

```nginx
server {
    listen 443 ssl;
    server_name sentinel.example.com;

    ssl_certificate /etc/letsencrypt/live/sentinel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinel.example.com/privkey.pem;

    location / {
        proxy_pass http://dashboard:8050;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://controller:5000;
    }
}
```

---

## Step 3: Deploy

```bash
# Set profile
export SENTINEL_PROFILE=prod

# Start production stack
docker-compose -f ops/docker-compose.prod.yml up -d

# Verify health
curl -k https://localhost/api/v1/health
```

---

## Step 4: Database Migrations

```bash
# Run migrations
docker-compose exec controller python -m alembic upgrade head

# Verify schema
docker-compose exec postgres psql -U postgres -d sentinel -c "\dt"
```

---

## Trusted Proxy Configuration

When behind a reverse proxy, configure trusted proxy headers:

```python
# controller/app.py
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,      # Number of proxy hops
    x_proto=1,
    x_host=1,
    x_prefix=1
)
```

Environment variable:
```
TRUSTED_PROXY_COUNT=1
```

---

## Security Checklist

- [ ] All secrets in `.env` (not defaults)
- [ ] TLS enabled on all external endpoints
- [ ] Database not exposed externally
- [ ] Redis not exposed externally
- [ ] Sensor auth tokens unique per sensor
- [ ] Firewall rules configured
- [ ] Log retention policy set

---

## Next Steps

- [Operations Runbook](runbook.md) - Day-to-day operations
- [Data Lifecycle](data_lifecycle.md) - Backup and retention
