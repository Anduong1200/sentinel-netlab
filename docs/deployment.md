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

Configuration is managed via `config.yaml` mounted into the containers.

```yaml
# config.yaml snippet
api:
  host: "0.0.0.0"
  port: 5000
  # Security: Change this!
  api_key: "${API_KEY_ENV_VAR}" 
```

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
docker-compose pull
docker-compose up -d
```
