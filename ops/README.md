# Sentinel NetLab - Operations Configurations

This directory contains deployment and monitoring configurations.

## 📁 Structure

```
ops/
├── docker-compose.lab.yml      # Local lab stack (mock sensors)
├── docker-compose.prod.yml     # Production stack
├── docker-compose.dev.yml      # Development stack
├── docker-compose.sensor.yml   # Sensor-only stack
├── docker-compose.light.yml    # Lightweight stack
├── Dockerfile.sensor           # Sensor container
├── Dockerfile.controller       # Controller container
├── Dockerfile.dashboard        # Dashboard container
├── systemd/
│   └── sentinel-sensor.service # Linux systemd service
├── prometheus/
│   └── prometheus.yml          # Prometheus scrape config
└── filebeat/
    └── filebeat.yml            # Log shipping to ELK

## 🐳 Docker Deployment

The recommended way to deploy Sentinel NetLab.

```bash
# Build and start lab stack
docker compose -f ops/docker-compose.lab.yml up -d --build

# View logs
docker compose -f ops/docker-compose.lab.yml logs -f

# Stop
docker compose -f ops/docker-compose.lab.yml down
```

### Build Variants
- **Standard**: `ops/Dockerfile.sensor` (Debian-based, full feature)
- **Alpine**: `ops/Dockerfile.sensor.alpine` (Lightweight)
```

## 🚀 Systemd Service

Install and start the sensor as a system service:

```bash
# Copy service file
sudo cp ops/systemd/sentinel-sensor.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable sentinel-sensor
sudo systemctl start sentinel-sensor

# Check status
sudo systemctl status sentinel-sensor
journalctl -u sentinel-sensor -f
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

*See [resilience_and_performance.md](../docs/operations/resilience_and_performance.md) for metrics guidance and operational best practices.*
