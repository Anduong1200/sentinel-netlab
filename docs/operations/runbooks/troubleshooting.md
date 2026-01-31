# Troubleshooting Guide

## 1. Controller Startup Issues

### "Missing Secret Key"
**Error**: `RuntimeError: CONTROLLER_SECRET_KEY must be set in PRODUCTION mode`
**Fix**: Ensure `CONTROLLER_SECRET_KEY` and `CONTROLLER_HMAC_SECRET` are set in your environment variables or `.env` file. These are required for security in production.
```bash
export CONTROLLER_SECRET_KEY=your-secure-random-key
```

### "Database Connection Failed"
**Error**: `sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) connection to server... failed`
**Fix**:
1. Check if PostgreSQL container is running: `docker ps | grep postgres`
2. specific Verify `DATABASE_URL` format: `postgresql://user:pass@host:5432/dbname`
3. Ensure network connectivity between containers (if using Docker Compose).

## 2. Sensor Issues

### "Channel Switch Error" / "WinError 2"
**Error**: `[WinError 2] The system cannot find the file specified`
**Context**: This usually happens on Windows or when `iw` command is missing.
**Fix**:
- **Windows**: Use PCAP replay mode or ensure `channel_hop` is disabled in config (`capture.enable_channel_hop: false`).
- **Linux**: Install wireless tools: `sudo apt install wireless-tools`

### "Monitor Mode Failed"
**Error**: `Failed to enable monitor mode`
**Fix**:
1. Verify your adapter supports monitor mode: `sudo airmon-ng`
2. Kill interfering processes: `sudo airmon-ng check kill`
3. Manually enable: `sudo ip link set wlan0 down && sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up`

## 3. Authentication

### "401 Unauthorized"
**Fix**:
- Verify `SENSOR_AUTH_TOKEN` matches a valid API key in the controller's database.
- Check if the key has expired (rotate keys using `scripts/rotate_keys.py`).
- Ensure system clocks are synchronized (HMAC/JWT often requires time sync).

## 4. performance

### High CPU Usage
**Cause**: Too many frames or complex ML model.
**Fix**:
- Reduce channel hop rate.
- Disable `ml_enabled` in `config.yaml` if running on low-power hardware (e.g., Pi Zero).
