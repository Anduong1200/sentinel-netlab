# Configuration Reference

Complete reference for all Sentinel NetLab configuration options.

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/sentinel/config.yaml` | Main configuration |
| `/etc/sentinel/env` | Environment variables (secrets) |
| `sensor/risk_weights.yaml` | Risk scoring weights |

---

## Main Configuration (config.yaml)

```yaml
# =============================================================================
# Sentinel NetLab Sensor Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# Sensor Identity
# -----------------------------------------------------------------------------
sensor:
  id: "sensor-01"              # Unique identifier (required)
  interface: "wlan0"           # WiFi interface (required)

# -----------------------------------------------------------------------------
# Capture Settings
# -----------------------------------------------------------------------------
capture:
  method: "scapy"              # scapy | tshark
  channels: [1, 6, 11]         # Channel list for hopping
  dwell_ms: 200                # Time per channel (ms)
  hop_enabled: true            # Enable channel hopping

# -----------------------------------------------------------------------------
# Buffer & Journal
# -----------------------------------------------------------------------------
buffer:
  max_items: 10000             # Ring buffer capacity
  storage_path: "/var/lib/sentinel/journal"
  max_disk_mb: 100             # Maximum journal disk usage
  drop_policy: "oldest"        # oldest | none

# -----------------------------------------------------------------------------
# Transport
# -----------------------------------------------------------------------------
transport:
  upload_url: "http://controller:5000/api/v1/telemetry"
  timeout_sec: 30              # HTTP timeout
  retry_max: 5                 # Maximum retry attempts
  backoff_base_sec: 1.0        # Initial backoff delay

# -----------------------------------------------------------------------------
# Upload Batching
# -----------------------------------------------------------------------------
upload:
  batch_size: 200              # Records per batch
  interval_sec: 5.0            # Upload interval
  compress: true               # gzip compression

# -----------------------------------------------------------------------------
# Privacy
# -----------------------------------------------------------------------------
privacy:
  anonymize_ssid: false        # Hash SSIDs
  anonymize_mac: false         # Hash client MACs

# -----------------------------------------------------------------------------
# Detection
# -----------------------------------------------------------------------------
detection:
  evil_twin_enabled: true
  deauth_flood_enabled: true
  deauth_threshold: 10         # Frames per second
  ssid_similarity_threshold: 0.8

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging:
  level: "INFO"                # DEBUG | INFO | WARNING | ERROR
  format: "json"               # json | text
```

---

## Environment Variables

Store secrets in `/etc/sentinel/env`:

```bash
# Authentication
BEARER_TOKEN=your-secure-token

# Optional: Client certificate for mTLS
CLIENT_CERT=/etc/sentinel/certs/client.pem
CLIENT_KEY=/etc/sentinel/certs/client.key

# Optional: Controller CA certificate
CA_CERT=/etc/sentinel/certs/ca.pem
```

---

## CLI Flags

Override configuration via command line:

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Config file path | `config.yaml` |
| `--sensor-id` | Sensor identifier | from config |
| `--iface` | WiFi interface | from config |
| `--channels` | Channel list (comma-separated) | `1,6,11` |
| `--dwell-ms` | Channel dwell time | `200` |
| `--upload-url` | Controller endpoint | from config |
| `--mock-mode` | Use mock capture driver | `false` |
| `--log-level` | Logging level | `INFO` |
| `--anonymize-ssid` | Enable SSID hashing | `false` |

### Examples

```bash
# Basic operation
python cli.py --sensor-id rpi-01 --iface wlan0

# Custom channels
python cli.py --sensor-id rpi-01 --iface wlan0 --channels 1,6,11,36,40,44

# Development mode
python cli.py --sensor-id dev --iface mock0 --mock-mode --log-level DEBUG
```

---

## Risk Weights (risk_weights.yaml)

Customize threat scoring:

```yaml
# Weight multipliers for risk factors (0.0 - 1.0)
weights:
  encryption_score: 0.25       # Weight for encryption strength
  rssi_score: 0.10             # Signal strength factor
  vendor_trust: 0.15           # Known vendor bonus
  ssid_suspicious: 0.20        # Suspicious SSID patterns
  wps_enabled: 0.10            # WPS vulnerability
  beacon_anomaly: 0.20         # Beacon interval variance

# Thresholds for risk levels
thresholds:
  high: 70                     # Score >= 70 = HIGH risk
  medium: 40                   # Score >= 40 = MEDIUM risk
  # Score < 40 = LOW risk

# Trusted vendors (OUI prefixes)
trusted_vendors:
  - "00:1A:2B"  # Cisco
  - "00:50:56"  # VMware
  - "DC:A6:32"  # Raspberry Pi

# Suspicious SSID patterns (regex)
suspicious_patterns:
  - "^Free.*WiFi$"
  - "^xfinity.*$"
  - "(?i)guest"
```

---

## Recommended Configurations

### High-Security Lab

```yaml
capture:
  channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # All 2.4GHz
  dwell_ms: 100

detection:
  deauth_threshold: 5
  ssid_similarity_threshold: 0.9

privacy:
  anonymize_ssid: true
  anonymize_mac: true
```

### Wardriving

```yaml
capture:
  channels: [1, 6, 11, 36, 40, 44, 48]
  dwell_ms: 150

buffer:
  max_items: 50000
  max_disk_mb: 500
```

### Low-Resource (Pi Zero)

```yaml
capture:
  channels: [1, 6, 11]
  dwell_ms: 500

buffer:
  max_items: 1000
  max_disk_mb: 50

upload:
  batch_size: 50
  interval_sec: 30
```
