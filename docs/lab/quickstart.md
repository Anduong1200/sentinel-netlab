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
*   **Hardware**: 4GB RAM minimum allocated to Docker.

---

## 2. Start the Lab in 2 Steps

This lab runs safely on your localhost.

### Step 1: Generate Secrets (Once)
```bash
python ops/gen_lab_secrets.py
```

### Step 2: Start the Stack
```bash
docker compose -f ops/docker-compose.lab.yml up -d --build
```

*Wait about 30 seconds for the "Proxy" to become healthy.*

### Step 3: Seed Scenario Data (Optional)
To load the "Deauth Attack" scenario:
```bash
docker compose -f ops/docker-compose.lab.yml run --rm seed
```

---

## 3. Access the Lab

The entire lab is exposed on **ONE** localhost port:

*   **Dashboard**: [http://127.0.0.1:8080](http://127.0.0.1:8080)
*   **API Health**: [http://127.0.0.1:8080/api/v1/health](http://127.0.0.1:8080/api/v1/health)

*(Note: Ports 5000 and 8050 are NOT exposed to your host anymore. Everything goes through the Proxy.)*

---

## 4. Resetting the Lab

To wipe all data and start fresh:

```bash
# 1. Stop and remove volumes
docker compose -f ops/docker-compose.lab.yml down -v

# 2. Restart
docker compose -f ops/docker-compose.lab.yml up -d

# 3. Re-seed (if desired)
docker compose -f ops/docker-compose.lab.yml run --rm seed
```

---

## 5. Stop (Keep Data)

```bash
docker compose -f ops/docker-compose.lab.yml down
```

---

## 🔗 Troubleshooting

See **[Troubleshooting Guide](troubleshooting.md)**.

### How this is tested
*CI runs exactly these commands: `up`, `run seed`, then checks `localhost:8080`.*
