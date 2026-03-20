# Lab Quickstart Guide

> **Target Audience**: Students, Researchers, Developers
> **Scope**: Localhost only, Offline-first, Mock Sensors allowed.

---

## 🚀 What You Will Get

By following this guide (approx. 10 minutes), you will have:
1.  **Web UI (Dashboard)** running at `http://127.0.0.1:8080/dashboard/`.
2.  **Controller API** receiving telemetry at `http://127.0.0.1:8080/api/v1`.
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
*   **Hardware**: 2+ Cores, 4GB RAM minimum allocated to Docker. See **[Hardware & Software Requirements](../reference/hardware_requirements.md)** for detailed specs (including VM setups).

---

## 2. Fastest Path: One Run Only

This lab runs safely on your localhost, and the fastest bootstrap is a single command from the repo root:

```bash
python one_run.py --open-browser
```

What this does for you:
- creates or reuses `venv/`
- installs the runtime dependencies for sensor + controller + dashboard
- generates `ops/.env.lab` if it does not exist yet
- starts the lab stack and initializes the database
- seeds the demo scenario on the first run
- generates runtime tokens for the dashboard and TUI
- writes local helper files: `.env`, `config.yaml`, `.sentinel_tui_profiles.json`, `run_tui.sh`, `open_dashboard.sh`
- falls back to a TUI-only mock bootstrap if Docker/Compose is missing or your shell cannot reach the Docker daemon yet

After the first bootstrap, your normal entrypoints are:

```bash
./run_tui.sh
./open_dashboard.sh
```

If you rerun bootstrap later, it reuses the local state file `.sentinel_one_run_state.json` to skip dependency reinstall and demo reseed. Use `python one_run.py --force` if you want a full rebuild.

## 3. Manual Lab Start (Advanced)

If you prefer the explicit Docker flow, you can still do it step by step.

### Step 1: Generate Secrets (Once)
```bash
python ops/gen_lab_secrets.py
```

### Step 2: Start the Stack
```bash
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml up -d --build
```

*Wait about 30 seconds for the "Proxy" to become healthy.*

### Step 3: Seed Scenario Data (Optional)
To load the "Deauth Attack" scenario:
```bash
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml run --rm seed
```

---

## 4. Access the Lab

The entire lab is exposed on **ONE** localhost port:

*   **Dashboard**: [http://127.0.0.1:8080](http://127.0.0.1:8080)
*   **API Health**: [http://127.0.0.1:8080/api/v1/health](http://127.0.0.1:8080/api/v1/health)

*(Note: Ports 5000 and 8050 are NOT exposed to your host anymore. Everything goes through the Proxy.)*

---

## 5. Optional: Use a Real Sensor (No Mock)

By default, `ops/docker-compose.lab.yml` starts a mock sensor (`SENSOR_MOCK_MODE=true`).
If you want real telemetry from a physical adapter:

```bash
# 1) Ensure lab DB has bootstrap admin token (admin-token-dev)
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml exec -T controller python ops/init_lab_db.py

# 2) Stop mock sensor container
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml stop sensor

# 3) Auto-create fresh dashboard + sensor runtime tokens, then refresh dashboard
make lab-gen-runtime-tokens SENSOR_ID=sensor-real-01
```

Then run your physical sensor process on Linux host/VM using that `SENSOR_ID`.
See **[Testing Guide](testing_guide.md)** for the end-to-end command flow.

---

## 6. Resetting the Lab

To wipe all data and start fresh:

```bash
# 1. Stop and remove volumes
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml down -v

# 2. Restart
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml up -d

# 3. Re-seed (if desired)
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml run --rm seed
```

---

## 7. Stop (Keep Data)

```bash
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml down
```

---

## 🔗 Troubleshooting

See **[Troubleshooting Guide](troubleshooting.md)**.

### How this is tested
*CI runs exactly these commands: `up`, `run seed`, then checks `localhost:8080`.*
