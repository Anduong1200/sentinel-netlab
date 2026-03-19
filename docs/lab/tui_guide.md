# Sentinel NetLab — TUI User Guide

## Overview

The **Sentinel NetLab TUI** (Text-based User Interface) is a professional terminal-based command center for monitoring, controlling, and testing the entire Sentinel NetLab system directly from the terminal. It is designed for environments without a graphical desktop (Raspberry Pi, SSH sessions, penetration testing distros).

## Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Launch the TUI
python -m sensor.tui
```

## Screen Flow

### Screen 1: Setup & Pre-flight Check

When the TUI boots, it automatically:
- **Loads repo `.env` defaults** from `.env` (or `sensor/.env`) when available
- **Scans for WiFi interfaces** (`/sys/class/net/*/wireless`)
- **Checks Controller status** (is the Docker lab online?)
- **Loads previous configuration** from `config.yaml`

You then choose an operation mode:

| Mode | Description |
|------|-------------|
| **(A) Live Combat** | Uses real WiFi card, enables full packet capture |
| **(B) Mock / Test** | Simulated data, no hardware required |
| **(C) PCAP Replay** | Re-analyze a saved `.pcap` capture file |

**Feature toggles:**
- `[ ] Enable ML Boost` — Turn on machine learning classification
- `[ ] Enable Geo-Location` — GPS coordinate enrichment
- `[x] Anonymize MAC/SSID` — Privacy mode for production use

**Validation:** The TUI will **block start** if:
- Live mode selected but no WiFi card detected
- PCAP mode selected but file path is empty or invalid
- Geo-Location enabled but Sensor X/Y coordinates are missing

Press **F5** or click **START** to begin.

Set `SENTINEL_ENV_FILE=/path/to/custom.env` before launch if you want the TUI to load a different env file.

### Screen 2: Live Dashboard (4 Panels)

```
┌──────────────────┬────────────────────────────────┬───────────────────┐
│ 🖥️ SYSTEM HEALTH │ 📶 LIVE NETWORK FEED           │ 📄 LOG STREAM     │
│                  │                                │                   │
│ CPU: 12%         │ Time   BSSID    SSID    RSSI   │ [10:45:01] INFO   │
│ RAM: 45%         │ 10:45  AA:BB..  MyWiFi  -42    │ Batch #42 sent    │
│ USB: wlan0mon    │ 10:44  CC:DD..  Guest   -68    │ [10:45:02] WARN   │
│ Uptime: 00:15:32 │ 10:44  EE:FF..  OPEN    -81    │ Spool backlog: 5  │
│                  ├──────────────────┬─────────────┤                   │
│ 📦 SPOOL QUEUE   │ 🚨 THREAT ALERTS │ 🛰️ WARDRIVE │                   │
│ Queued: 3        │ [10:44] CRITICAL │ walker-01   │                   │
│ Inflight: 1      │ Evil Twin...     │ Nets: 24    │                   │
│ Dropped: 0       │ [10:43] MEDIUM   │ GPS: 18     │                   │
│                  │ Deauth Burst     │ Last fix... │                   │
│ 🔒 SECURITY      │                  │ Recent APs  │                   │
│ Open: 2 (RED)    │                  │             │                   │
│ WEP: 1 (ORANGE)  │                  │             │                   │
│ WPA2: 15 (CYAN)  │                  │             │                   │
│ WPA3: 3 (GREEN)  │                  │             │                   │
└──────────────────┴──────────────────┴─────────────┴───────────────────┘
                    [ F1 Setup  F2/C Channel  SPACE Pause  M Mark  Q Quit ]
```

## Keybindings

| Key | Action |
|-----|--------|
| **F1** | Return to Setup screen |
| **F5** | Start sensor (on Setup screen) |
| **Space** | Pause/Resume log scrolling |
| **M** | Mark selected BSSID as suspicious |
| **F2 / C** | Force WiFi channel hop |
| **Q** | Graceful shutdown (animated) |

## Wardrive Feed

If `wardrive_session.json` exists in the project root, the dashboard follows it automatically and shows:
- Session sensor ID, unique networks, total sightings, and GPS-point count
- Last GPS fix and last sighting timestamp
- The newest wardrive sightings with security color hints

Set `WARDRIVE_SESSION_FILE=/path/to/session.json` before launching the TUI to watch a different session file.

## Alert Debouncing

To prevent "Alert Fatigue", the TUI automatically groups duplicate alerts within a 10-second window. Instead of showing:
```
🚨 Deauth Burst
🚨 Deauth Burst
🚨 Deauth Burst
🚨 Deauth Burst
🚨 Deauth Burst
```

It displays:
```
🚨 Deauth Burst
🚨 Deauth Burst (5x)
```

## Graceful Shutdown

When pressing **Q** on the Dashboard, the TUI does NOT exit immediately. It shows a shutdown sequence:
1. 🔄 Stopping Sensor Worker…
2. 📦 Flushing Spool Queue…
3. 💾 Saving state…
4. 📡 Closing network card…

This ensures no data is lost during shutdown.

## Architecture

```
[ TUI Main Thread ]  ←── Queues / Callbacks ───  [ SensorController Worker Thread ]
        ↓                                                  ↓
  Textual Widgets                                   Capture, Parse, Upload
  (DataTable, RichLog)                              Live status + alerts
```

The TUI runs as the **main process**. When you press START, it boots a background worker thread that instantiates `SensorController` directly with the selected mode and feature toggles. Communication happens via:
- **Log Queue** — `TUILogHandler` captures Python logging output
- **Alert Queue** — Alerts are forwarded from the controller callback bridge
- **Network Queue** — Live network discoveries are pushed from the exporter path
- **Wardrive File Watch** — `wardrive_session.json` is reloaded on refresh to surface GPS/mobile capture data
- **Status Sync** — The dashboard polls `controller.status()` for spool, channel, and USB health

## Files

| File | Purpose |
|------|---------|
| `sensor/tui/__init__.py` | Package marker |
| `sensor/tui/__main__.py` | Entry point for `python -m sensor.tui` |
| `sensor/tui/app.py` | Main Textual App, Screens, and refresh logic |
| `sensor/tui/state_manager.py` | Thread-safe AppState + TUILogHandler |
| `sensor/tui/theme.tcss` | Dark SOC theme stylesheet |
