# Configuration Reference

This document describes all configuration parameters available in `config.example.yaml`.

Copy `config.example.yaml` to `config.yaml` and modify as needed.

---

## `capture` - WiFi Capture Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | string | `wlan0` | Wireless interface name (must support monitor mode) |
| `channels` | list[int] | `[1, 6, 11]` | WiFi channels to scan (2.4GHz: 1-14, 5GHz: 36-165) |
| `dwell_time` | float | `0.4` | Seconds to stay on each channel before hopping |
| `enable_channel_hop` | bool | `true` | Enable automatic channel hopping |
| `scan_duration` | int | `10` | Duration (seconds) for each scan cycle |
| `packet_filter` | string | `"type mgt"` | BPF filter for packet capture (default: management frames only) |

---

## `storage` - Data Persistence

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `db_path` | string | `./data/wifi_scans.db` | Path to SQLite database (Standalone mode) |
| `pcap_dir` | string | `./data/pcaps` | Directory for PCAP file storage |
| `pcap_enabled` | bool | `true` | Enable raw packet capture to PCAP files |
| `pcap_max_age_days` | int | `7` | Delete PCAP files older than N days |
| `pcap_max_size_mb` | int | `100` | Maximum size per PCAP file before rotation |
| `history_retention_days` | int | `30` | Days to retain scan history in database |

---

## `api` - API Server Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | `0.0.0.0` | Bind address for API server |
| `port` | int | `5000` | Port number for API server |
| `debug` | bool | `false` | Enable Flask debug mode (**disable in production**) |
| `api_key` | string | `change-me-in-production` | API key for authentication |
| `rate_limit` | string | `60/minute` | Rate limiting rule (e.g., `100/hour`, `10/second`) |
| `cors_enabled` | bool | `true` | Enable CORS headers for cross-origin requests |
| `ssl_enabled` | bool | `true` | Enable HTTPS (requires `ssl_cert` and `ssl_key`) |
| `ssl_cert` | string | `/etc/ssl/certs/sentinel.crt` | Path to SSL certificate file |
| `ssl_key` | string | `/etc/ssl/private/sentinel.key` | Path to SSL private key file |

---

## `risk` - Risk Scoring Weights

These weights control the ML-based risk scoring algorithm. Must sum to 1.0.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `encryption_weight` | float | `0.45` | Weight for encryption strength factor |
| `signal_weight` | float | `0.20` | Weight for signal strength anomalies |
| `ssid_weight` | float | `0.15` | Weight for suspicious SSID patterns |
| `vendor_weight` | float | `0.10` | Weight for vendor reputation |
| `channel_weight` | float | `0.10` | Weight for channel anomalies |
| `high_risk_threshold` | int | `70` | Score >= this triggers "High" severity |
| `critical_risk_threshold` | int | `90` | Score >= this triggers "Critical" severity |

---

## `privacy` - Data Privacy Controls

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | string | `anonymized` | Privacy mode: `normal`, `anonymized`, `private` |
| `store_raw_mac` | bool | `false` | Store raw MAC addresses (GDPR consideration) |
| `anonymize_ssid` | bool | `false` | Hash SSIDs before storage |
| `retention_days` | int | `30` | Days to retain data before deletion |

### Privacy Modes

| Mode | Behavior |
|------|----------|
| `normal` | Full data stored as-is |
| `anonymized` | MAC addresses hashed, GPS truncated |
| `private` | Minimal data retention, no PII stored |

---

## Global Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mock_mode` | bool | `false` | Enable mock data generation (for testing) |
| `log_level` | string | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Environment Variable Overrides

Some parameters can be overridden via environment variables:

| Config Key | Environment Variable |
|------------|---------------------|
| `api.api_key` | `CONTROLLER_SECRET_KEY` |
| `log_level` | `LOG_LEVEL` |
| `mock_mode` | `MOCK_MODE` |

---

*See also: [Installation Guide](../getting-started/installation.md) | [Threat Model](../architecture/threat_model.md)*
