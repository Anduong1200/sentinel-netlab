# Lab Reset & Seed Guide

> **How `make lab-reset` works and what data it creates.**

---

## Quick Reference

```bash
# Full reset (wipe + reseed)
make lab-reset

# Just restart (keep data)
make lab-down && make lab-up
```

---

## What `make lab-reset` Does

| Step | Action | Command |
|------|--------|---------|
| 1 | Stop containers | `docker-compose down` |
| 2 | Remove volumes | `docker volume prune` |
| 3 | Regenerate secrets | `python ops/gen_lab_secrets.py` |
| 4 | Initialize database | `python ops/init_lab_db.py` |
| 5 | Seed demo data | `python ops/seed_lab_data.py` |
| 6 | Start containers | `docker-compose up -d` |

---

## Seeded Data

### Sensor
| Field | Value |
|-------|-------|
| ID | `sensor-01` |
| Name | Lab Demo Sensor |
| Location | Lab Environment |

### Telemetry

Loaded from `examples/sample_telemetry_output.json`:

- ~10 beacon frames
- Mixed SSIDs (CorpNet, GuestWiFi)
- Various RSSI levels

### Alerts

Loaded from `examples/sample_alert_output.json`:

- 1 Evil Twin alert (CorpNet)
- Severity: HIGH
- Full evidence chain

---

## Default Credentials

| Service | Username | Password/Token |
|---------|----------|----------------|
| Dashboard | admin | See `.env.lab` → `DASH_PASSWORD` |
| API | - | `admin` (token hash) |
| Postgres | postgres | See `.env.lab` → `POSTGRES_PASSWORD` |

---

## Data Locations

| Data | Location | Persisted? |
|------|----------|------------|
| SQLite DB | `ops/lab.db` | No (wiped on reset) |
| Secrets | `ops/.env.lab` | Yes (regenerated if missing) |
| Logs | Docker volumes | No (wiped on reset) |

---

## Custom Seeding

To add your own demo data:

1. Create JSON files in `examples/`:
   - `my_telemetry.json` (same format as `sample_telemetry_output.json`)
   - `my_alerts.json` (same format as `sample_alert_output.json`)

2. Modify `ops/seed_lab_data.py` to load your files

3. Run `make lab-reset`

---

## Troubleshooting Reset

| Issue | Solution |
|-------|----------|
| Reset hangs | Run `docker-compose down -v --remove-orphans` |
| Data still there | Check `ops/lab.db` was deleted |
| Secrets error | Delete `ops/.env.lab` and re-run |
