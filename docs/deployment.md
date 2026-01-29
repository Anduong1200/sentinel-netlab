# Deployment Guide

This guide covers deploying Sentinel NetLab using Docker and Docker Compose. We support two main deployment modes:

1.  **Full Stack (Controller + Sensor + Dashboard)**: Recommended for the central server.
2.  **Sensor Only (Lightweight)**: Optimized for Raspberry Pi or edge devices.

## Prerequisites

-   Docker Engine 20.10+
-   Docker Compose v2.0+
-   Git

## 1. Quick Start (Full Stack)

This deploys the complete environment including the Controller API, Time-Series Database (Prometheus), Redis, and the Grafana/Dash Dashboard.

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Set up environment variables
cp ops/.env.example ops/.env
# Edit ops/.env to set secure passwords (POSTGRES_PASSWORD, REDIS_PASSWORD, etc.)

# Start services
docker-compose -f ops/docker-compose.yml up -d
```

### Services Started:
-   **controller**: REST API (Port 5000)
-   **dashboard**: Analysis UI (Port 8050)
-   **postgres**: Metadata storage
-   **redis**: Task queue
-   **prometheus**: Metrics
-   **filebeat**: Log shipping (optional)

## 2. Sensor Deployment (Raspberry Pi)

For edge devices capturing WiFi traffic, use the lightweight sensor configuration.

```bash
# On the Raspberry Pi
cd sentinel-netlab

# Set up environment
cp ops/.env.example ops/.env
# Ensure CONTROLLER_URL in .env points to your Full Stack server

# Start Sensor
docker-compose -f ops/docker-compose.sensor.yml up -d
```

**Note on Hardware Access**: The sensor container runs in `privileged` mode to access the WiFi adapter directly. Ensure your host interface (e.g., `wlan1`) is capable of monitor mode.

## 3. Configuration

We strictly enforce configuration via environment variables for secrets.

### Required Production Secrets
You **MUST** set these in your orchestration system (Docker Secrets / K8s Secrets). **Do NOT commit them to git.**

```bash
ENVIRONMENT=production
CONTROLLER_SECRET_KEY=<long-random-string>
CONTROLLER_HMAC_SECRET=<long-random-string>
CONTROLLER_DATABASE_URL=postgresql://user:pass@db:5432/sentinel
```

If any of these are missing in `production` mode, the controller will **refuse to start**.

### Optional Overrides
- `CONTROLLER_PORT`: Default 5000
- `REQUIRE_TLS`: Default true
- `TOKEN_EXPIRY_HOURS`: Default 720 (30 days)

## 4. Troubleshooting

**Logs**:
```bash
docker-compose -f ops/docker-compose.yml logs -f controller
```

**Sensor Connectivity**:
Check if the sensor can reach the controller:
```bash
curl http://<controller-ip>:5000/health
```

**Update Images**:
Our CI/CD pipeline publishes images to GitHub Container Registry (GHCR). To pull the latest stable release:
```bash
docker-compose up -d
```

## 5. Manual Installation (Development / Bare Metal)

If you prefer running without Docker (e.g., for local development or custom hardware integration):

```bash
# 1. Install System Dependencies
sudo apt-get install libpq-dev tcpdump wireless-tools

# 2. Setup Python Environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Sentinel NetLab (Editable Mode)
# This installs all packages (sensor, controller, algos, ml) and dependencies
pip install -e .[dev,ml]

# 4. Initialize Database (for Controller)
export CONTROLLER_DATABASE_URL=sqlite:///sentinel.db
export ENVIRONMENT=development
python -c "from controller.api_server import app, db; app.app_context().push(); db.create_all(); from controller.api.auth import init_default_tokens; init_default_tokens()"

# 5. Run Services
# Controller
python -m controller.api_server

# Sensor (in another terminal)
python -m sensor.sensor_cli --mock-mode
```
