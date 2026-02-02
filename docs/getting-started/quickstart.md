# Quickstart Guide

> Get Sentinel NetLab running in 15 minutes

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| Controller | Docker + docker-compose OR Python 3.11+ |
| Sensor | Raspberry Pi 4 (2GB+) + USB WiFi adapter |
| Network | Sensors can reach controller on port 5000 |

---

## 1. Controller Setup (Docker - Recommended)

```bash
# Clone repository
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Configure secrets
cp .env.example .env
# Edit .env: set CONTROLLER_SECRET_KEY and CONTROLLER_HMAC_SECRET
# Generate with: openssl rand -hex 32

# Start stack (includes Postgres, Redis, Prometheus, Grafana)
cd ops && docker-compose up -d

# Verify
curl http://localhost:5000/api/v1/health
- Python 3.11+
- Linux (for Sensor) or Windows/Mac (for Controller/Dashboard)
- WiFi Adapter supporting Monitor Mode (e.g., Alfa AWUS036ACM) - see [Hardware Guide](../reference/hardware_compatibility.md) (Stub)

> [!NOTE]
> See [Threat Model](../architecture/threat_model.md) for security scope.

## Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/anduong1200/sentinel-netlab.git
    cd sentinel-netlab
    ```

2.  **Set up Virtual Environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    Select the installation based on your role:

    ```bash
    # For Controller (Server)
    pip install ".[controller]"

    # For Sensor (Capture Device)
    pip install ".[sensor]"

    # For Dashboard (UI)
    pip install ".[dashboard]"

    # For Development (Tests, Linting)
    pip install ".[dev]"
    ```

4.  **Install Logic**
    (Included in step 3 via `.` install)

---

## 2. Sensor Setup (Raspberry Pi)

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3.11 python3-venv python3-pip aircrack-ng git

# Clone repository
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure sensor
cp config.example.yaml config.yaml
# Edit config.yaml:
#   sensor.id: "pi-sensor-01"
#   controller.url: "http://YOUR_CONTROLLER_IP:5000"
# Copy HMAC secret from controller .env

# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Note: interface becomes wlan0mon

# Start sensor
sudo python sensor/main.py --interface wlan0mon
```

---

## 3. Verify Connection

```bash
# On controller - list connected sensors
curl -H "Authorization: Bearer admin-token-dev" \
     http://localhost:5000/api/v1/sensors

# Expected output:
# {"count": 1, "sensors": {"pi-sensor-01": {"status": "online", ...}}}
```

---

## 4. View Alerts

```bash
# Get recent alerts
curl -H "Authorization: Bearer admin-token-dev" \
     http://localhost:5000/api/v1/alerts?limit=10

# Or open Grafana dashboard
open http://localhost:3000
```

---

## 5. Run in Mock Mode (No Hardware)

```bash
# For testing without WiFi adapter
python sensor/main.py --mock

# Generates synthetic network data
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Start controller | `cd ops && docker-compose up -d` |
| Stop controller | `cd ops && docker-compose down` |
| View logs | `docker-compose logs -f controller` |
| Enable monitor mode | `sudo airmon-ng start wlan0` |
| Start sensor | `sudo python sensor/main.py --interface wlan0mon` |
| Run tests | `make test` |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Sensor can't connect | Check firewall, verify controller URL |
| No frames captured | Verify monitor mode: `iw dev wlan0mon info` |
| Auth error (401) | Check token validity, regenerate if expired |
| High CPU on Pi | Reduce channel hop rate in config.yaml |

---

## Next Steps

1. Read [Hardware Prerequisites](installation.md#prerequisite-hardware)
2. Review [Threat Model](../architecture/threat_model.md)
3. Configure [Alert Rules](../../ops/alert_rules.yml)
4. Set up [Grafana Dashboards](../../ops/grafana/dashboards/)

---

*Need help? Open an issue on GitHub.*
