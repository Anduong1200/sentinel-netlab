# Configuration Reference

The system is configured via `config/sensor.yaml` and Environment Variables.

## Sensor Configuration (`config/sensor.yaml`)
```yaml
network:
    interface: "wlan1"      # Monitor mode interface
    mon_interface: "mon0"  # (Optional) Created automatically

detection:
    evil_twin:
        whitelist: []       # BSSIDs to ignore
    dos:
        threshold: 10       # Frames/sec

reporting:
    interval: 5             # Seconds between uploads
```

## Environment Variables (`.env`)
- `CONTROLLER_URL`: URL of the API (e.g., `https://192.168.1.10:5000`)
- `SENSOR_ID`: Unique ID (e.g., `sensor-01`)
- `SENSOR_TOKEN`: JWT/Bearer token for API auth.
- `CONTROLLER_HMAC_SECRET`: Shared secret for signing.
