# Sentinel NetLab - Lab Quickstart

> **One command to start learning.** This is the official guide for running Sentinel NetLab in Lab Mode.

---

## Prerequisites

- **Docker** (v20.10+) and **Docker Compose** (v2.x)
- **Make** (for Makefile targets)
- **Python 3.11+** (for local scripts if running outside Docker)
- ~4 GB RAM available

---

## Quick Start (10 Minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab
```

### 2. Start the Lab

```bash
make lab-up
```

This command will:
1. Generate secure secrets (`.env.lab`) if they don't exist.
2. Initialize the SQLite database with the schema.
3. Seed demo data (sensors, telemetry, alerts).
4. Start all services: **Controller**, **Dashboard**, **Worker**, **Sensor (Mock)**, **Postgres**, **Redis**.

### 3. Access the Dashboard

Open your browser:

- **Dashboard**: [http://127.0.0.1:8050](http://127.0.0.1:8050)
- **Controller API**: [http://127.0.0.1:5000/api/v1/health](http://127.0.0.1:5000/api/v1/health)

**Default Login** (Lab Mode):
- Username: `admin`
- Password: (check `ops/.env.lab` for `DASH_PASSWORD`)

---

## Lab Commands

| Command           | Description                                      |
|-------------------|--------------------------------------------------|
| `make lab-up`     | Start the lab (builds, seeds, runs)              |
| `make lab-down`   | Stop all containers                              |
| `make lab-logs`   | Tail logs from all services                      |
| `make lab-reset`  | **Wipe all data** and restart with fresh seed    |

---

## What's Running?

| Service     | Port (localhost) | Description                          |
|-------------|------------------|--------------------------------------|
| Dashboard   | 8050             | UI for viewing alerts, sensors, map  |
| Controller  | 5000             | REST API for ingestion and queries   |
| Sensor      | (internal)       | Mock sensor generating fake traffic  |
| Postgres    | (internal)       | TimescaleDB for telemetry storage    |
| Redis       | (internal)       | Cache and queue                      |
| Worker      | (internal)       | Background task processor            |

> **Safe by Default**: Only Dashboard (8050) and Controller (5000) are exposed on `127.0.0.1`. Database and Redis are NOT accessible from LAN.

---

## Lab Exercises

### Exercise 1: View Demo Data

1. Navigate to the **Overview** page in the Dashboard.
2. You should see the seeded sensor (`sensor-01`) and at least one alert ("Evil Twin Detected").

### Exercise 2: Explore Alerts

1. Click on the **Threats** page.
2. Review the sample "Evil Twin" alert.
3. Note the **MITRE ATT&CK** mapping and **Evidence** fields.

### Exercise 3: Reset the Lab

If you make changes or corrupt the database:

```bash
make lab-reset
```

This returns the lab to its initial state.

---

## Troubleshooting

See [docs/lab/troubleshooting.md](./troubleshooting.md) for common issues.

**Quick Fixes**:
- **Containers won't start?** Run `docker compose logs` to see errors.
- **Dashboard shows no data?** Run `make lab-reset` to re-seed.
- **Port already in use?** Stop conflicting services or change ports in `.env.lab`.

---

## Next Steps

- **Hardware Mode**: See `docs/lab_mode/authorization.md` for using real WiFi adapters (authorized labs only).
- **Detection Development**: See `docs/dev_detectors.md` for writing custom rules.
- **API Reference**: See `docs/api.md`.

---

*Last updated: 2026-02-06*
