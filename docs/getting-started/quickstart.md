# Quickstart Guide

> [!IMPORTANT]
> This is the **Canonical Guide** for starting Sentinel NetLab in Production/Lab mode.
> For specific Lab features, see [docs/lab](../lab/README.md).

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

### Step 3: Start the Stack
Use the main hardened compose file.

```bash
docker compose -f ops/docker-compose.yml up -d
```

### Step 4: Verify Deployment
The stack uses Nginx as the single entry point.

- **URL**: `https://localhost` (Self-signed certs)
- **Grafana**: `https://localhost/grafana/` (Login with credentials from `.env`)
- **Controller API**: `https://localhost/api/v1/health`
- **Dashboard**: `https://localhost/dashboard/`

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
     host: "CONTROLLER_IP" # Nginx IP
     port: 443
     ssl_enabled: true
     api_key: "YOUR_SENSOR_TOKEN" # Create via Admin API
   ```
3. **Run**:
   ```bash
   python -m sensor.sensor_controller --config-file config.yaml
   ```

## 4. Next Steps

- [Lab Guide](../lab/README.md) - For isolated attack simulations.
- [Sensor Guide](../reference/sensor_config.md) - Detailed hardware setup.
- [Troubleshooting](../lab/troubleshooting.md) - Common issues.
