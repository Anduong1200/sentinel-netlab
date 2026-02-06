# Lab Reset & Seeding Guide

> **Command**: `make lab-reset`
> **Purpose**: Restore the lab environment to a clean, predictable state for training or demos.

---

## 🛑 What Happens During Reset?

When you run `make lab-reset`, the system performs a **destructive** cleanup followed by a fresh initialization.

### 1. Destructive Actions (Wipe)
*   **Stops Containers**: All running lab containers are stopped.
*   **Removes Volumes**: The persistent volumes for:
    *   Database (`postgres_data`) -> **ALL telemetry and alerts are deleted.**
    *   Redis (`redis_data`) -> **Queue is cleared.**
    *   Grafana (`grafana_data`) -> **Dashboards reset to defaults.**

### 2. Initialization Actions (Re-init)
*   **Regenerate Secrets**: New random keys for `CONTROLLER_SECRET_KEY` and `POSTGRES_PASSWORD` are generated in `.env.lab`.
*   **Initialize Database**: The SQLite schema is recreated from scratch.

### 3. Seeding (Load Data)
*   **Default Admin**: Creates `admin` user (API Token: `admin-token-dev`).
*   **Sample Data**:
    *   Injects a "Gold Standard" PCAP replay scenario.
    *   Creates synthetic **Alerts** (Evil Twin, Deauth Flood).
    *   Creates synthetic **Telemetry** (Beacons, Probes).

---

## 🧩 Default Seed Data

After a reset, your environment is pre-populated with:

### Sensors
*   `sensor-mock-01`: A virtual sensor actively reporting data.

### Alerts
| Severity | Type | Title | Description |
| :--- | :--- | :--- | :--- |
| **High** | `evil_twin` | Potential Evil Twin AP | SSID 'FreeWifi' seen with mismatched BSSID/Vendor. |
| **Critical** | `deauth_flood` | Deauth Flood Detected | Excessive deauth frames targeting 'Corporate-Guest'. |

### Networks
*   `FreeWifi` (Open, High Risk)
*   `Corporate-Guest` (WPA2, Secure)

---

## 🛠 Manual Seeding (Advanced)

If you want to re-seed data *without* wiping the database (e.g., to add more noise), you can run:

```bash
# Run the seeder script independently
python ops/seed_lab_data.py
```

*Note: This may create duplicate records if run multiple times without a reset.*

---

## ❓ Frequently Asked Questions

**Q: Will `make lab-reset` affect my production deployment?**
A: **No.** The reset script explicitly targets `docker-compose.lab.yml` and `.env.lab`. Production config is separate.

**Q: Can I customize the seed data?**
A: Yes, modify `ops/seed_lab_data.py`. It uses standard Python `requests` to push data to the Controller API.
