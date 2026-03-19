# Release Notes — v1.0.0 (2026-03-19)

**Sentinel NetLab v1.0.0** introduces a professional Text-based User Interface (TUI) for terminal-only environments, fixes critical dashboard rendering issues, adds financial-style real-time analytics, and marks the first major stable release.

## 🚀 Highlights

### 1. Terminal Command Center (TUI)
- Full **Textual** framework TUI at `sensor/tui/` — run via `python -m sensor.tui`.
- **Setup Screen (Pre-flight Check)**: Choose operation mode (Live Combat / Mock Test / PCAP Replay), configure WiFi interface, toggle ML/Geo/Anonymization — all without CLI flags.
- **Dashboard Screen (4 Panels)**:
  - 🖥️ System Health: CPU%, RAM%, USB Watchdog, Spool Queue (queued/inflight/dropped).
  - 📶 Live Network Feed: Color-coded DataTable (RSSI: 🟢>-50 / 🟡-50~-70 / 🔴<-70; Security: Red=Open, Orange=WEP, Cyan=WPA2, Green=WPA3).
  - 🚨 Threat Alerts: Real-time streaming with severity color-coding.
  - 📄 Log Stream: Full sensor log routing via custom `QueueHandler`.
- **Keybindings**: `F1` Setup / `F5` Start / `Space` Pause / `Q` Quit.
- **Dark SOC Theme**: GitHub-style dark stylesheet.

### 2. Dashboard Signal Analysis Redesign
- Replaced random mock 24h network discovery graph with **real `first_seen` timestamp binning**.
- Added **Plotly financial-style charts**: `rangeselector` (5m/15m/30m/1H) + `rangeslider` for interactive time zoom.
- Fixed RSSI chart by correcting field mapping `rssi` → `rssi_avg`.

### 3. Map & Heatmap Rendering Fix
- Overview Heatmap and Global Intelligence Map now **always render** even when sensors lack GPS hardware.
- Deterministic fallback coordinates generated from BSSID MD5 hash.
- Security Pie Chart crash on empty data fixed.

### 4. Dashboard Hardening
- Added Flask `secret_key` to resolve auth session warnings.
- Re-enabled Audit tab navigation.
- Added `dashboard/pages/audit.py` for System Audit Logs.

### 5. Detection Fixes
- Fixed `frame_type` vs `frame_subtype` mismatch for deauth detection in `SensorController`.
- Fixed `DeauthFloodDetector` state persistence causing false negatives across test runs.

## 🛠 Upgrade Notes

### From v0.5.x
- **New dependency**: `pip install textual rich` (or `pip install -e ".[sensor]"`)
- **No breaking changes** — TUI is additive, all existing CLI and web dashboard functionality preserved.
- Run `cd ops && docker compose --env-file .env.lab -f docker-compose.lab.yml up --build -d dashboard` to apply dashboard fixes.

## 📝 Quick Start — TUI
```bash
source venv/bin/activate
python -m sensor.tui
```

## 📚 Documentation
- [Testing Guide](docs/lab/testing_guide.md) — Updated with presentation script
- [CHANGELOG](CHANGELOG.md) — Full v1.0.0 entry

---

# Release Notes — v0.5.0 (2026-02-25)

**Sentinel NetLab v0.5.0** expands the detection pipeline from 8 to 11 detectors, adds 39 new unit tests, and completes comprehensive documentation cleanup for release.

## 🚀 Highlights

### 1. Three New Attack Detectors
- **Disassociation Flood** (`disassoc_detector.py`): Sliding-window rate analysis with multi-client severity escalation. MITRE T1499.001.
- **Beacon Flood / Fake AP** (`beacon_flood_detector.py`): Detects mass fake SSID broadcasts from tools like mdk3/mdk4. MITRE T1498.001.
- **KRACK** (`krack_detector.py`): Key Reinstallation Attack via EAPOL M3 retransmission + M3-after-M4 replay detection. CVE-2017-13077. MITRE T1557.002.

### 2. Expanded Test Coverage
- **159 unit tests** (up from 120), including 39 new tests across 4 test files
- Dedicated Evil Twin detector unit tests (11 tests) — previously had zero
- All detector tests follow consistent pattern: threshold, cooldown, severity, evidence, reset

### 3. Documentation Overhaul
- Complete rewrite of detection docs, algorithms README, and developer guide
- All 11 detectors documented with MITRE ATT&CK IDs
- Updated pipeline architecture diagram

### 4. Code Quality
- 10 lint errors fixed across test files
- MITRE ATT&CK ID added to `DeauthFloodAlert`
- Removed tracked junk files (`.dos_state.json`, `ruff.log`, `test_migration_v6.db`)

## 🛠 Upgrade Notes

### From v0.4.x
- **No breaking changes** — all additions are backward-compatible
- Three new detectors are automatically enabled in the sensor pipeline

---

# Release Notes — v0.4.0 (2026-02-14)

## 🚀 Highlights

### 1. Release Audit — 45 Bugs Fixed
Five systematic audit passes across 130+ production Python files:
-   **5 Critical Operational Bugs**: Capture thread death, alert data loss pipeline, schema rejection at API boundary
-   **Datetime Hygiene**: All timestamp generation now uses timezone-aware `datetime.now(UTC)`
-   **Logger Hygiene**: Removed all `logging.basicConfig()` calls from library modules (prevents root logger hijacking)
-   **Deprecated API**: Replaced `datetime.utcfromtimestamp()` with `datetime.fromtimestamp(tz=UTC)`
-   **Verification**: `ruff check`, `pytest` — all green

### 2. Dashboard Refactor
-   Refactored monolithic `app.py` into Dash Multi-Page App architecture
-   Pages: **Overview**, **Map**, **Threats**, **Signals**
-   Components: **Sidebar**, **Cards**

### 3. Hardened Security Architecture
-   **Trusted Proxy Model**: Explicit IP attribution/spoofing protection via `TRUSTED_PROXY_CIDRS`
-   **Strict TLS & HMAC**: Enforced HTTPS and Request Signing (`REQUIRE_TLS`, `REQUIRE_HMAC`)
-   **Fail-Fast Config**: Startup aborts immediately if secrets are missing or weak
-   **Least Privilege**: Non-root containers, read-only volumes where possible
-   **CI Security**: Trivy vulnerability fixes in Docker image layers

### 4. Observability Stack
-   **Structured Logging**: JSON logs with PII redaction (SSID, Tokens)
-   **Metrics**: Standardized Prometheus metrics (`ingest_*`, `queue_*`, `worker_*`)
-   **Correlation**: Distributed tracing via `X-Request-ID` and `X-Batch-ID`
-   **Dashboards**: Grafana ready (Ingest Health, Queue Lag)

### 5. Scalability
-   Database indexing and partitioning strategies
-   Bulk ingest endpoint for high-throughput sensor deployments
-   Background worker queue infrastructure

## 🛠 Upgrade Notes

### From v0.3.x
-   **No breaking changes** — all fixes are backward-compatible
-   All `logging.basicConfig` removals may affect standalone script usage — configure logging in your entry point

### From Beta/Dev
-   **Config Change**: `.env` structure has changed. Use `.env.example` as a reference
-   **Database**: Run `docker compose up migration` to align schema

## 📝 Configuration Checklist
1.  Generate Secrets: `openssl rand -hex 32` for `CONTROLLER_SECRET_KEY` etc.
2.  Set `TRUSTED_PROXY_CIDRS` if behind a Load Balancer
3.  Set `SENTINEL_LAB_MODE=true` only for isolated research environments

## 📚 Documentation
-   [Deployment Guide](docs/prod/deployment.md)
-   [Observability Contract](docs/reference/observability.md)
-   [Configuration Reference](docs/reference/configuration.md)
