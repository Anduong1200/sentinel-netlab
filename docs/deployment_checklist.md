# Sentinel NetLab - Deployment Verification Checklist

Use this checklist to verify a successful sensor deployment.

## Pre-deployment

- [ ] Hardware supported (see docs/supported_hardware.md)
- [ ] WiFi adapter supports monitor mode
- [ ] Linux host OS (Debian/Ubuntu recommended)
- [ ] Network connectivity to controller

## User & Permissions

- [ ] `sentinel` user exists and owns `/opt/sentinel`
  ```bash
  id sentinel
  ls -la /opt/sentinel
  ```

- [ ] Directories have correct permissions:
  - `/opt/sentinel` - sentinel:sentinel
  - `/etc/sentinel` - root:sentinel (750)
  - `/var/lib/sentinel/journal` - sentinel:sentinel (750)

## Code & Dependencies

- [ ] Python venv created at `/opt/sentinel/venv`
  ```bash
  /opt/sentinel/venv/bin/python --version
  ```

- [ ] Requirements installed
  ```bash
  /opt/sentinel/venv/bin/pip list | grep scapy
  ```

## Configuration

- [ ] `/etc/sentinel/config.yaml` present and readable
  ```bash
  ls -la /etc/sentinel/config.yaml
  cat /etc/sentinel/config.yaml | grep sensor_id
  ```

- [ ] `/etc/sentinel/env` present with correct permissions (640 root:sentinel)
  ```bash
  ls -la /etc/sentinel/env
  ```

## Helper Scripts

- [ ] `sentinel-ensure-monitor-mode` installed and executable
  ```bash
  ls -la /usr/local/bin/sentinel-ensure-monitor-mode
  /usr/local/bin/sentinel-ensure-monitor-mode --help || echo "Script exists"
  ```

## Systemd Service

- [ ] Unit file installed
  ```bash
  ls -la /etc/systemd/system/sentinel-sensor*.service
  ```

- [ ] Service enabled and active
  ```bash
  sudo systemctl enable --now sentinel-sensor@wlan0.service
  sudo systemctl status sentinel-sensor@wlan0.service
  ```

## Monitor Mode

- [ ] Interface in monitor mode
  ```bash
  iw dev | grep -A5 wlan0
  # Should show: type monitor
  ```

## Logs & Health

- [ ] Service logs visible in journal
  ```bash
  sudo journalctl -u sentinel-sensor@wlan0.service -n 20
  ```

- [ ] No startup errors
  ```bash
  sudo journalctl -u sentinel-sensor@wlan0.service | grep -i error
  ```

- [ ] Health endpoint responds (if implemented)
  ```bash
  curl -s http://127.0.0.1:9100/health
  ```

## Functional Tests

- [ ] Test mode runs without errors
  ```bash
  sudo -u sentinel /opt/sentinel/venv/bin/python \
    /opt/sentinel/sensor/cli.py \
    --config /etc/sentinel/config.yaml \
    --iface wlan0 --mock-mode
  ```

- [ ] Journal directory accumulates data
  ```bash
  ls -la /var/lib/sentinel/journal/
  ```

## Network Outage Recovery

- [ ] Stop controller, wait for sensor to buffer
- [ ] Verify journal files created
- [ ] Restart controller
- [ ] Verify batches uploaded and journals cleaned

## Security

- [ ] `/etc/sentinel/env` not world-readable
  ```bash
  stat -c "%a" /etc/sentinel/env
  # Should be 640
  ```

- [ ] TLS enabled for upload (check config)
- [ ] Bearer token is not default value

---

**Date:** ____________  
**Deployed by:** ____________  
**Sensor ID:** ____________  
**Interface:** ____________
