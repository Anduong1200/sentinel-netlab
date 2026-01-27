# Deployment Guide

Production deployment procedures for Sentinel NetLab sensors.

---

## Deployment Checklist

### Pre-Deployment

- [ ] Hardware tested (see [Hardware Compatibility](hardware.md))
- [ ] Network connectivity verified
- [ ] Controller endpoint accessible
- [ ] SD card prepared with OS image

### Installation

- [ ] Setup script completed (`./scripts/setup.sh`)
- [ ] `sentinel` user created and owns directories
- [ ] Python venv created and requirements installed
- [ ] Configuration files present and secured

### Configuration

- [ ] `/etc/sentinel/config.yaml` customized
- [ ] `/etc/sentinel/env` contains secure token
- [ ] Permissions are correct (640 for secrets)

### Service

- [ ] Systemd unit installed
- [ ] Service enabled: `systemctl enable sentinel-sensor@wlan0`
- [ ] Service starts without errors
- [ ] Monitor mode activates successfully

### Verification

- [ ] `iw dev` shows monitor mode active
- [ ] Logs show frame capture
- [ ] Controller receives telemetry
- [ ] Metrics endpoint responds (if enabled)

---

## Systemd Service Management

### Start/Stop/Restart

```bash
# Start sensor
sudo systemctl start sentinel-sensor@wlan0.service

# Stop sensor
sudo systemctl stop sentinel-sensor@wlan0.service

# Restart sensor
sudo systemctl restart sentinel-sensor@wlan0.service

# Enable on boot
sudo systemctl enable sentinel-sensor@wlan0.service
```

### Check Status

```bash
# Service status
sudo systemctl status sentinel-sensor@wlan0.service

# View logs
sudo journalctl -u sentinel-sensor@wlan0.service -f

# View recent logs
sudo journalctl -u sentinel-sensor@wlan0.service -n 100
```

### Multiple Interfaces

```bash
# Enable multiple sensors
sudo systemctl enable sentinel-sensor@wlan0.service
sudo systemctl enable sentinel-sensor@wlan1.service

# Check all instances
sudo systemctl list-units 'sentinel-sensor@*'
```

---

## Security Hardening

### File Permissions

```bash
# Configuration files
sudo chmod 640 /etc/sentinel/config.yaml
sudo chmod 640 /etc/sentinel/env
sudo chown root:sentinel /etc/sentinel/*

# Certificates (if using mTLS)
sudo chmod 600 /etc/sentinel/certs/*
sudo chown root:sentinel /etc/sentinel/certs/*
```

### Network Security

- Use HTTPS for controller communication
- Consider mTLS for sensor authentication
- Rotate bearer tokens periodically
- Firewall unused ports

### Process Isolation

The systemd unit includes:
- `PrivateTmp=true` - Isolated temp directory
- `ProtectSystem=strict` - Read-only system
- `ProtectHome=true` - No access to home dirs
- `NoNewPrivileges=true` - No privilege escalation

---

## Monitoring

### Health Endpoint

If enabled, metrics are available at:
```
http://localhost:9100/metrics
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `sentinel_frames_captured_total` | Total frames captured |
| `sentinel_buffer_size` | Current buffer occupancy |
| `sentinel_upload_success_total` | Successful uploads |
| `sentinel_upload_failed_total` | Failed uploads |
| `sentinel_last_upload_timestamp` | Last upload time |

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sentinel-sensors'
    static_configs:
      - targets:
        - 'sensor1.local:9100'
        - 'sensor2.local:9100'
```

---

## Troubleshooting

### Service Won't Start

1. Check config syntax:
   ```bash
   python -c "import yaml; yaml.safe_load(open('/etc/sentinel/config.yaml'))"
   ```

2. Check interface exists:
   ```bash
   ip link show wlan0
   ```

3. Check permissions:
   ```bash
   sudo -u sentinel cat /etc/sentinel/config.yaml
   ```

### No Frames Captured

1. Verify monitor mode:
   ```bash
   iw dev wlan0 info | grep type
   ```

2. Check channel:
   ```bash
   iw dev wlan0 info | grep channel
   ```

3. Test with tcpdump:
   ```bash
   sudo tcpdump -i wlan0 -c 5 type mgt
   ```

### Upload Failures

1. Test controller connectivity:
   ```bash
   curl -v http://controller:5000/health
   ```

2. Check auth token:
   ```bash
   curl -H "Authorization: Bearer $BEARER_TOKEN" http://controller:5000/api/v1/status
   ```

3. Review journal for queued batches:
   ```bash
   ls -la /var/lib/sentinel/journal/
   ```

### High Memory Usage

1. Reduce buffer size:
   ```yaml
   buffer:
     max_items: 5000
   ```

2. Increase upload frequency:
   ```yaml
   upload:
     interval_sec: 2.0
   ```

---

## Backup & Recovery

### Configuration Backup

```bash
# Backup config
sudo tar -czf sentinel-config-$(date +%Y%m%d).tar.gz /etc/sentinel/

# Restore
sudo tar -xzf sentinel-config-*.tar.gz -C /
```

### Journal Recovery

Journals are automatically replayed after restart:
```bash
# Check pending journals
ls -la /var/lib/sentinel/journal/

# Force replay
sudo systemctl restart sentinel-sensor@wlan0.service
```

---

## Upgrade Procedure

```bash
# Stop service
sudo systemctl stop sentinel-sensor@wlan0.service

# Run upgrade script
sudo ./scripts/upgrade.sh

# Start service
sudo systemctl start sentinel-sensor@wlan0.service

# Verify
sudo journalctl -u sentinel-sensor@wlan0.service -f
```
