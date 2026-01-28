# Deployment Checklist

> Pre-deployment verification for Sentinel NetLab sensors

---

## 📋 Environment Setup

- [ ] Ubuntu 22.04 LTS / Raspberry Pi OS Lite installed
- [ ] Python 3.9+ installed (`python3 --version`)
- [ ] WiFi adapter connected and detected (`lsusb`)
- [ ] Monitor mode driver installed (see `docs/hardware_compatibility.md`)

## 🔐 Security Configuration

- [ ] TLS certificates configured (Let's Encrypt or self-signed)
- [ ] Environment variables set:
  - [ ] `SENSOR_AUTH_TOKEN` - API authentication token
  - [ ] `SENSOR_HMAC_SECRET` - Payload signing secret (optional)
  - [ ] `CONTROLLER_URL` - Controller endpoint (https://...)
- [ ] Firewall rules configured (only allow outbound HTTPS)
- [ ] Non-root user created for sensor service

## 📡 Sensor Verification

Run these tests before production deployment:

```bash
# 1. Verify monitor mode
sudo iw dev wlan1 set type monitor
iw dev wlan1 info | grep type  # Should show: type monitor

# 2. Test capture (30 seconds)
cd sensor && python -c "
from capture_driver import MockCaptureDriver
driver = MockCaptureDriver('wlan1mon')
driver.enable_monitor_mode()
print('Monitor mode: OK')
"

# 3. Test controller connectivity
curl -k -H "Authorization: Bearer $SENSOR_AUTH_TOKEN" \
     https://controller:5000/api/v1/health
```

## 🚀 Service Deployment

- [ ] Systemd unit file installed (`/etc/systemd/system/sentinel-sensor.service`)
- [ ] Service enabled: `sudo systemctl enable sentinel-sensor`
- [ ] Service started: `sudo systemctl start sentinel-sensor`
- [ ] Logs verified: `journalctl -u sentinel-sensor -f`

## 🔍 Post-Deployment Validation

- [ ] Telemetry appearing in controller dashboard
- [ ] Alerts generating for test scenarios
- [ ] Prometheus metrics accessible (`/metrics`)
- [ ] No authentication errors in logs

---

## ⚠️ Common Issues

| Symptom | Check |
|---------|-------|
| No frames captured | Monitor mode, antenna, channel |
| Upload failures | Network, auth token, TLS cert |
| High CPU | Reduce channel hop rate |
| Service crashes | Check logs, memory limits |

---

*Last Updated: January 28, 2026*
