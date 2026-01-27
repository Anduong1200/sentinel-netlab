# Sentinel NetLab - Operator Guide

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r sensor/requirements.txt
```

### 2. Configure Adapter

```bash
# Put adapter in monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw wlan0 set channel 6
```

### 3. Start Sensor

```bash
# Basic start
cd sensor
sudo python cli.py --sensor-id rpi-lab-01 --iface wlan0

# With specific channels
sudo python cli.py --sensor-id rpi-lab-01 --iface wlan0 --channels 1,6,11

# Mock mode (no hardware)
python cli.py --sensor-id test-01 --iface mock0 --mock-mode
```

---

## Configuration

### Config File (sensor/config.yaml)

```yaml
sensor:
  id: "sensor-01"
  interface: "wlan0"

capture:
  channels: [1, 6, 11]   # Non-overlapping 2.4GHz
  dwell_ms: 200          # Time per channel
  method: "scapy"        # scapy | tshark

buffer:
  max_items: 10000
  storage_path: "/var/lib/sentinel/journal"

transport:
  upload_url: "http://controller:5000/api/v1/telemetry"
  auth_token: "your-secure-token"

privacy:
  anonymize_ssid: false  # Hash SSIDs
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--sensor-id` | Unique sensor identifier (required) |
| `--iface` | Network interface (required unless --mock-mode) |
| `--channels` | Comma-separated channel list |
| `--dwell-ms` | Channel dwell time in milliseconds |
| `--upload-url` | Controller endpoint URL |
| `--auth-token` | Authentication token |
| `--mock-mode` | Use mock capture driver |
| `--anonymize-ssid` | Hash SSIDs for privacy |
| `--log-level` | DEBUG, INFO, WARNING, ERROR |
| `--config-file` | Path to YAML config file |

---

## Monitoring

### Health Endpoint

```bash
curl http://localhost:9100/metrics
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `sentinel_frames_captured_total` | Total frames captured |
| `sentinel_buffer_size` | Current buffer occupancy |
| `sentinel_upload_success_total` | Successful uploads |
| `sentinel_upload_failed_total` | Failed uploads |

---

## Deployment

### Systemd Service

```bash
# Install service
sudo cp ops/systemd/wifi-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wifi-scanner
sudo systemctl start wifi-scanner

# Check status
sudo systemctl status wifi-scanner
journalctl -u wifi-scanner -f
```

### Docker (Controller Only)

```bash
cd packaging/docker
docker-compose up -d
```

---

## Troubleshooting

### Sensor won't start

1. Check interface exists: `ip link`
2. Verify monitor mode: `iw dev wlan0 info | grep type`
3. Check permissions: must run as root for monitor mode

### No frames captured

1. Check channel: `iw dev wlan0 info | grep channel`
2. Verify there are APs nearby: `iw dev wlan0 scan`
3. Check driver: `dmesg | tail -20`

### Upload failures

1. Check controller is reachable: `curl http://controller:5000/health`
2. Verify auth token matches
3. Check journal for queued batches

---

## Best Practices

1. **Place sensors strategically** - Cover all areas of interest
2. **Use non-overlapping channels** - 1, 6, 11 for 2.4GHz
3. **Monitor buffer usage** - Increase if seeing drops
4. **Rotate journals** - Clean up old journals periodically
5. **Secure auth tokens** - Use unique tokens per sensor
