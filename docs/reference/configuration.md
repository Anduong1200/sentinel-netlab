# Configuration Reference

This document describes configuration parameters for Sentinel NetLab sensor and controller runtime.

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

> These weights control the risk scoring algorithm. See [Risk Scoring Model](../architecture/risk_scoring.md) for the full mathematical framework.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `encryption_weight` | float | `0.40` | Weight for encryption strength factor |
| `signal_weight` | float | `0.15` | Weight for signal strength anomalies |
| `ssid_weight` | float | `0.08` | Weight for suspicious SSID patterns |
| `vendor_weight` | float | `0.10` | Weight for vendor reputation |
| `channel_weight` | float | `0.04` | Weight for channel anomalies |
| `beacon_anomaly_weight` | float | `0.12` | Weight for beacon interval variance |
| `wps_weight` | float | `0.06` | Weight for WPS vulnerability |
| `hidden_flag_weight` | float | `0.05` | Weight for hidden SSID flag |
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

## `geo` - Sensor Geo Pipeline

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | `false` | Enable geo pipeline inside sensor processing loop |
| `environment` | string | `indoor_los` | Path-loss profile for RSSI-to-distance modeling |
| `sensor_x_m` | float | `null` | Sensor local X coordinate (meters, east axis) |
| `sensor_y_m` | float | `null` | Sensor local Y coordinate (meters, north axis) |
| `sensor_z_m` | float | `0.0` | Sensor height (meters) |
| `origin_lat` | float | `null` | Optional map origin latitude for local->GPS projection |
| `origin_lon` | float | `null` | Optional map origin longitude for local->GPS projection |
| `heatmap_enabled` | bool | `false` | Enable heatmap accumulation/export |
| `heatmap_width_m` | float | `50.0` | Heatmap width in meters |
| `heatmap_height_m` | float | `50.0` | Heatmap height in meters |
| `heatmap_resolution_m` | float | `1.0` | Grid resolution in meters |
| `heatmap_export_path` | string | `/var/lib/wifi-scanner/geo_heatmap.json` | JSON export output path |
| `heatmap_export_interval_sec` | int | `60` | Export interval (seconds) |

When geo is enabled on a sensor, missing `sensor_x_m`/`sensor_y_m` causes fail-fast startup error.

---

## Controller Distributed Geo Settings

| Env Key | Type | Description |
|---------|------|-------------|
| `GEO_ENABLED` | bool | Enable controller-side distributed geo enrichment |
| `SENSOR_POSITIONS_JSON` | JSON | Static sensor coordinates map used for trilateration/fallback |
| `GEO_ORIGIN_LAT` | float | Optional latitude origin for x/y -> lat/lon projection |
| `GEO_ORIGIN_LON` | float | Optional longitude origin for x/y -> lat/lon projection |
| `GEO_SAMPLE_WINDOW_SEC` | int | Time window for per-BSSID sample grouping |

Example:

```bash
SENSOR_POSITIONS_JSON='{"sensor-01":{"x":0,"y":0},"sensor-02":{"x":20,"y":0},"sensor-03":{"x":10,"y":17.3}}'
GEO_ORIGIN_LAT=10.776889
GEO_ORIGIN_LON=106.700806
```

Geo method semantics:
- If >=3 positioned sensors exist for a BSSID in the sample window: `trilateration+kalman`.
- If <3 sensors are available: fallback `strongest_rssi` at strongest sensor position.

---

## Global Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mock_mode` | bool | `false` | Enable mock data generation (for testing) |
| `log_level` | string | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Environment Variable Overrides

| Config Key | Environment Variable |
|------------|---------------------|
| `api.api_key` | `CONTROLLER_SECRET_KEY` |
| `log_level` | `LOG_LEVEL` |
| `mock_mode` | `MOCK_MODE` |
| `geo.enabled` | `SENSOR_GEO_ENABLED` |
| `geo.sensor_x_m` | `SENSOR_GEO_X_M` |
| `geo.sensor_y_m` | `SENSOR_GEO_Y_M` |
| `geo.sensor_z_m` | `SENSOR_GEO_Z_M` |
| `geo.heatmap_enabled` | `SENSOR_GEO_HEATMAP_ENABLED` |
| `geo.heatmap_width_m` | `SENSOR_GEO_HEATMAP_WIDTH_M` |
| `geo.heatmap_height_m` | `SENSOR_GEO_HEATMAP_HEIGHT_M` |
| `geo.heatmap_resolution_m` | `SENSOR_GEO_HEATMAP_RESOLUTION_M` |
| `geo.heatmap_export_path` | `SENSOR_GEO_HEATMAP_EXPORT_PATH` |
| `geo.heatmap_export_interval_sec` | `SENSOR_GEO_HEATMAP_EXPORT_INTERVAL_SEC` |

---

*See also: [Installation Guide](../getting-started/installation.md) | [Threat Model](../architecture/threat_model.md)*
