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

Press **F5** or click **START** to begin.

### Screen 2: Live Dashboard (4 Panels)

```
┌──────────────────┬────────────────────────────────┬───────────────────┐
│ 🖥️ SYSTEM HEALTH │ 📶 LIVE NETWORK FEED           │ 📄 LOG STREAM     │
│                  │                                │                   │
│ CPU: 12%         │ Time   BSSID    SSID    RSSI   │ [10:45:01] INFO   │
│ RAM: 45%         │ 10:45  AA:BB..  MyWiFi  -42    │ Batch #42 sent    │
│ USB: wlan0mon    │ 10:44  CC:DD..  Guest   -68    │ [10:45:02] WARN   │
│ Uptime: 00:15:32 │ 10:44  EE:FF..  OPEN    -81    │ Spool backlog: 5  │
│                  │                                │                   │
│ 📦 SPOOL QUEUE   ├────────────────────────────────┤                   │
│ Queued: 3        │ 🚨 THREAT ALERTS               │                   │
│ Inflight: 1      │                                │                   │
│ Dropped: 0       │ [10:44] 🚨 CRITICAL            │                   │
│                  │ Evil Twin Detected - AA:BB...   │                   │
│ 🔒 SECURITY      │                                │                   │
│ Open: 2 (RED)    │ [10:43] ⚠️ MEDIUM              │                   │
│ WEP: 1 (ORANGE)  │ Deauth Burst (50x)             │                   │
│ WPA2: 15 (CYAN)  │                                │                   │
│ WPA3: 3 (GREEN)  │                                │                   │
└──────────────────┴────────────────────────────────┴───────────────────┘
                         [ F1 Setup  SPACE Pause  M Mark  C Channel  Q Quit ]
```

## Keybindings

| Key | Action |
|-----|--------|
| **F1** | Return to Setup screen |
| **F5** | Start sensor (on Setup screen) |
| **Space** | Pause/Resume log scrolling |
| **M** | Mark selected BSSID as suspicious |
| **C** | Force WiFi channel hop |
| **Q** | Graceful shutdown (animated) |

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
[ TUI Main Thread ]  ←── Queues ───  [ SensorController Worker Thread ]
        ↓                                        ↓
  Textual Widgets                         sensor/cli.py
  (DataTable, RichLog)                    (Capture, Parse, Upload)
```

The TUI runs as the **main process**. When you press START, it spawns a background subprocess running `sensor/cli.py`. Communication happens via:
- **Log Queue** — `TUILogHandler` captures Python logging output
- **Alert Queue** — Threat alerts pushed by `AlertManager`
- **Network Queue** — New network discoveries

## Files

| File | Purpose |
|------|---------|
| `sensor/tui/__init__.py` | Package marker |
| `sensor/tui/__main__.py` | Entry point for `python -m sensor.tui` |
| `sensor/tui/app.py` | Main Textual App, Screens, and refresh logic |
| `sensor/tui/state_manager.py` | Thread-safe AppState + TUILogHandler |
| `sensor/tui/theme.tcss` | Dark SOC theme stylesheet |
