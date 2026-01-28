# Operational Handbook

> Standard operating procedures for Sentinel NetLab deployment and operation

---

## Quick Reference

| Task | Command |
|------|---------|
| Start controller | `make docker-up` or `python controller/api_server.py` |
| Start sensor | `python sensor/main.py --interface wlan0mon` |
| View logs | `docker-compose logs -f controller` |
| Check health | `curl http://controller:5000/api/v1/health` |
| View alerts | `curl -H "Authorization: Bearer TOKEN" http://controller:5000/api/v1/alerts` |

---

## 1. Deployment Procedures

### 1.1 Controller Deployment

```bash
# 1. Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# 2. Configure secrets
cp .env.example .env
# Edit .env: set CONTROLLER_SECRET_KEY, CONTROLLER_HMAC_SECRET

# 3. Start with Docker
cd ops && docker-compose up -d

# 4. Verify health
curl http://localhost:5000/api/v1/health
```

### 1.2 Sensor Deployment (Raspberry Pi)

```bash
# 1. Install dependencies
sudo apt update && sudo apt install -y python3-pip aircrack-ng

# 2. Clone and configure
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab
cp config.example.yaml config.yaml
# Edit config.yaml with controller URL and credentials

# 3. Enable monitor mode
sudo airmon-ng start wlan0

# 4. Install service
sudo cp ops/systemd/sentinel-sensor.service /etc/systemd/system/
sudo systemctl enable sentinel-sensor
sudo systemctl start sentinel-sensor
```

### 1.3 Verify Deployment

```bash
# Controller health
curl http://controller:5000/api/v1/health

# Sensor registration
curl -H "Authorization: Bearer ADMIN_TOKEN" \
     http://controller:5000/api/v1/sensors

# Metrics
curl http://controller:9090/metrics
```

---

## 2. Daily Operations

### 2.1 Health Checks

```bash
# Automated via cron or monitoring
*/5 * * * * curl -sf http://controller:5000/api/v1/health || alert.sh
```

### 2.2 Log Review

```bash
# Controller logs
docker-compose logs --tail 100 controller

# Sensor logs
journalctl -u sentinel-sensor -n 100

# Search for errors
grep -i error /var/log/sentinel/*.log
```

### 2.3 Alert Triage

| Step | Action |
|------|--------|
| 1 | Review alert in dashboard or API |
| 2 | Assess severity (Critical → immediate, Info → batch) |
| 3 | Gather evidence (PCAP, frames) |
| 4 | Determine if true positive |
| 5 | Escalate or resolve |

---

## 3. Alert Response Playbooks

### 3.1 Evil Twin Detected

**Severity**: HIGH/CRITICAL

1. **Identify**: Note BSSID and SSID of suspected evil twin
2. **Locate**: Use RSSI triangulation from multiple sensors
3. **Isolate**: If in your environment, block MAC at switch/AP level
4. **Investigate**: Check for connected clients, data exfiltration
5. **Document**: Screenshot evidence, save PCAP
6. **Notify**: Security team, potentially legal/compliance

### 3.2 Deauth Flood Attack

**Severity**: CRITICAL

1. **Confirm**: Verify high deauth rate (>10/sec)
2. **Identify target**: Which AP/client is being attacked
3. **Enable PMF**: If possible, enable 802.11w on affected APs
4. **Physical search**: Attacker likely nearby
5. **Document**: Capture attack frames
6. **Report**: File incident report

### 3.3 Rogue AP Detected

**Severity**: MEDIUM/HIGH

1. **Verify**: Confirm AP not in inventory
2. **Locate**: Physical location via signal strength
3. **Assess**: Is it malicious or just unauthorized?
4. **Remove**: Physically disconnect if found
5. **Policy**: Remind staff of authorized device policy

---

## 4. Maintenance Procedures

### 4.1 Sensor Maintenance

```bash
# Update sensor software
cd /opt/sentinel-netlab
git pull
pip install -r requirements.txt
sudo systemctl restart sentinel-sensor

# Check adapter health
iw dev wlan0mon info
airmon-ng check

# Clear local spool
rm -rf data/spool/*
```

### 4.2 Controller Maintenance

```bash
# Database backup
docker exec sentinel-postgres pg_dump -U sentinel sentinel > backup_$(date +%Y%m%d).sql

# Update containers
docker-compose pull
docker-compose up -d

# Rotate logs
logrotate /etc/logrotate.d/sentinel
```

### 4.3 Certificate Rotation

```bash
# 1. Generate new cert
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout new-key.pem -out new-cert.pem -days 365

# 2. Deploy to controller
cp new-cert.pem /etc/sentinel/certs/server.crt
cp new-key.pem /etc/sentinel/certs/server.key
docker-compose restart controller

# 3. Update sensors with new CA
scp new-cert.pem pi@sensor:/etc/sentinel/ca.crt
ssh pi@sensor 'systemctl restart sentinel-sensor'
```

---

## 5. Troubleshooting

### 5.1 Sensor Issues

| Symptom | Check | Fix |
|---------|-------|-----|
| No frames captured | `iw dev wlan0mon info` | Re-enable monitor mode |
| High CPU | `top` | Reduce channel hop rate |
| Upload failures | Network connectivity | Check firewall, DNS |
| Service won't start | `journalctl -xe` | Check config syntax |

### 5.2 Controller Issues

| Symptom | Check | Fix |
|---------|-------|-----|
| 5xx errors | `docker logs controller` | Check config, restart |
| High memory | Prometheus | Clear telemetry buffer |
| Auth failures | Token expiry | Issue new tokens |
| Rate limited | Redis | Adjust limits |

### 5.3 Common Error Codes

| Code | Meaning | Resolution |
|------|---------|------------|
| 401 | Authentication failed | Check token validity |
| 403 | Permission denied | Check RBAC role |
| 400 | Validation error | Check payload schema |
| 429 | Rate limited | Wait or adjust limits |
| 502 | Controller down | Restart controller |

---

## 6. Emergency Procedures

### 6.1 Sensor Compromise

1. Immediately disconnect sensor from network
2. Revoke sensor's API token
3. Preserve logs for forensics
4. Replace sensor hardware if needed
5. Issue new credentials

### 6.2 Controller Compromise

1. Isolate controller server
2. Rotate all secrets (DB, HMAC, tokens)
3. Review audit logs
4. Redeploy from clean image
5. Re-register all sensors

### 6.3 Active Attack Response

1. Notify SOC/security team
2. Begin capture on affected sensors
3. Attempt physical locate of attacker
4. Document timeline
5. Preserve all evidence

---

*Last Updated: January 28, 2026*
