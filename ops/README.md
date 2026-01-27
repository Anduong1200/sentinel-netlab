# Sentinel NetLab - Operations Configurations

This directory contains deployment and monitoring configurations.

## 📁 Structure

```
ops/
├── systemd/
│   └── wifi-scanner.service    # Linux systemd service
├── prometheus/
│   └── prometheus.yml          # Prometheus scrape config
└── filebeat/
    └── filebeat.yml            # Log shipping to ELK
```

## 🚀 Systemd Service

Install and start the sensor as a system service:

```bash
# Copy service file
sudo cp ops/systemd/wifi-scanner.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable wifi-scanner
sudo systemctl start wifi-scanner

# Check status
sudo systemctl status wifi-scanner
journalctl -u wifi-scanner -f
```

## 📊 Prometheus Monitoring

```bash
# Copy config
sudo cp ops/prometheus/prometheus.yml /etc/prometheus/

# Restart Prometheus
sudo systemctl restart prometheus

# Access: http://localhost:9090
```

**Available Metrics:**
- `scan_duration_seconds` - Time per scan
- `networks_found_total` - Total networks detected
- `active_alerts` - Current alert count
- `risk_score_histogram` - Distribution of risk scores

## 📝 Filebeat (ELK Integration)

```bash
# Copy config
sudo cp ops/filebeat/filebeat.yml /etc/filebeat/

# Test config
sudo filebeat test config

# Start
sudo systemctl restart filebeat
```

**Log Index:** `sentinel-netlab-YYYY.MM.DD`

---

*See [metrics_guide.md](../docs/metrics_guide.md) for detailed metrics documentation.*
