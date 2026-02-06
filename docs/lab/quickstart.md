# Lab Quickstart Guide

> **Target Audience**: Students, Researchers, Developers
> **Scope**: Localhost only, Offline-first, Mock Sensors allowed.

---

## 🚀 What You Will Get

By following this guide (approx. 10 minutes), you will have:
1.  **Web UI (Dashboard)** running at `http://localhost:8050`.
2.  **Controller API** receiveing telemetry at `http://localhost:5000`.
3.  **Demo Data**: A pre-loaded scenario with simulated threats.
4.  **No Hardware Required**: The lab runs entirely in Docker with mock sensors.

---

## 🔒 Safety & Scope

*   **Localhost Only**: Services bind to `127.0.0.1`. Nothing is exposed to your LAN.
*   **Offline First**: No internet required after downloading Docker images.
*   **Mock Mode**: No WiFi adapter needed. We use simulated traffic replay.

> [!IMPORTANT]
> This environment is NOT for production. For real deployment, see **[Production Guide](../prod/deployment.md)**.
> Read the full [Safety Scope](safety.md).

---

## 1. Prerequisites

*   **Docker Desktop** (with Docker Compose v2)
*   **Make** (Optional, but recommended for ease of use)
*   **Hardware**: 4GB RAM minimum allocated to Docker.

---

## 2. Start the Lab ("Single Path")

We provide a unified command to generate secrets, initialize the database, and start the stack.

### Using Make (Recommended)

```bash
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab

# The ONE command to rule them all:
make lab-up
```

*Wait about 30 seconds for containers to initialize.*

### Manual Method (No Make)

```bash
# Generate secrets
python ops/gen_lab_secrets.py

# Initialize database
python ops/init_lab_db.py

# Start Docker Stack
docker compose -f ops/docker-compose.lab.yml up --build -d
```

---

## 3. Verify Health

1.  **Open the Dashboard**: [http://127.0.0.1:8050](http://127.0.0.1:8050)
    *   *Expected*: Dash UI loads. You may see empty charts initially or mock data flowing.
2.  **Check API Health**:
    ```bash
    curl http://127.0.0.1:5000/api/v1/health
    ```
    *   *Expected*: `{"ok": true, ...}`

---

## 4. First Scenario: "Golden PCAP"

The lab automatically starts a "Mock Sensor" (`sensor-mock-01`) that replays a standard attack scenario (`scenario_01`).

**Look for these Alerts in the Dashboard:**
*   **Evil Twin**: High Severity. A Rogue AP mimicking a known SSID.
*   **Deauth Flood**: Critical Severity. A burst of deauthentication frames.

*Trouble seeing data? Check the logs:*
```bash
make lab-logs
```

---

## 5. Resetting the Lab

Need a clean slate for a class or demo? **Reset everything** to the initial state.

```bash
make lab-reset
```

**What this does:**
1.  **Stops** all containers.
2.  **Wipes** Database and Queue volumes (destroys all data!).
3.  **Re-gens** new random secrets.
4.  **Seeds** the database with default admin user and clean state.
5.  **Restarts** the environment.

---

## 6. Stop & Cleanup

To stop the lab but **keep data**:
```bash
make lab-down
```

To stop and **remove volumes** (clean up disk space):
```bash
docker compose -f ops/docker-compose.lab.yml down -v
```

---

## 🔗 Troubleshooting

See **[Troubleshooting Guide](troubleshooting.md)** for common issues like port conflicts or Docker resource limits.

---

### How this is tested
*This quickstart is validated in CI by running `make lab-up`, checking health endpoints, and verifying seed data presence.*
