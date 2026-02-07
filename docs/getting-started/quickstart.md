# Quickstart Guide

> [!IMPORTANT]
> This quickstart focuses on **local lab/demo** usage. For production deployments, see
> the [Production Guide](../prod/deployment.md). For lab-specific details, see the
> [Lab Quickstart](../lab/quickstart.md).

---

## 1. Prerequisites

- **Docker** & **Docker Compose**
- **Git**
- **OpenSSL** (for generating secrets)

## 2. Setup & Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab
```

### Step 2: Configure Secrets
Create a `.env` file from the example. **You MUST set passwords**.

```bash
cp .env.example .env

# Generate secure keys
openssl rand -hex 32 # Use for CONTROLLER_SECRET_KEY
openssl rand -hex 32 # Use for CONTROLLER_HMAC_SECRET
```

> [!WARNING]
> Edit `.env` and set distinct passwords for `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MINIO_ROOT_PASSWORD`, and `GRAFANA_ADMIN_PASSWORD`.
> **The system will not start if these are missing.**

### Step 3: Start the Lab Stack
Use the lab compose file (local-only, mock sensors).

```bash
docker compose -f ops/docker-compose.lab.yml up -d --build
```

### Step 4: Verify Deployment
The lab stack uses a single proxy entry point.

- **Dashboard**: `http://127.0.0.1:8080`
- **API Health**: `http://127.0.0.1:8080/api/v1/health`

## 3. Sensor Connection

To connect a physical sensor (Raspberry Pi):

1. **Install Sensor Package**:
   ```bash
   pip install ".[sensor]"
   ```
2. **Configure**:
   ```yaml
   # config.yaml
   api:
     host: "CONTROLLER_IP"
     port: 5000
     ssl_enabled: false
     api_key: "YOUR_SENSOR_TOKEN"
   ```
3. **Run**:
   ```bash
   python -m sensor.sensor_controller --config-file config.yaml
   ```

## 4. Next Steps

- [Lab Guide](../lab/quickstart.md) - For isolated attack simulations.
- [Configuration Reference](../reference/configuration.md) - Detailed sensor/controller options.
- [Troubleshooting](../lab/troubleshooting.md) - Common issues.
