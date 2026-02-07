# Sentinel NetLab — Sensor Module

Lightweight WiFi capture agent for distributed intrusion detection.

---

## Overview

The sensor module is a standalone capture agent designed to run on:
- Raspberry Pi (primary target)
- Linux virtual machines
- Any Linux host with compatible WiFi adapter

It captures 802.11 management frames, processes them locally, and uploads telemetry to a central controller.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SENSOR AGENT                         │
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   Capture   │───▶│   Parser    │───▶│ Normalizer  │ │
│  │   Driver    │    │             │    │             │ │
│  └─────────────┘    └─────────────┘    └──────┬──────┘ │
│         │                                      │        │
│         │                                      ▼        │
│  ┌──────┴──────┐                      ┌─────────────┐  │
│  │   Channel   │                      │    Risk     │  │
│  │   Hopper    │                      │   Engine    │  │
│  └─────────────┘                      └──────┬──────┘  │
│                                              │         │
│                                              ▼         │
│                                       ┌─────────────┐  │
│                                       │   Buffer    │  │
│                                       │   Manager   │  │
│                                       └──────┬──────┘  │
│                                              │         │
│                                              ▼         │
│                                       ┌─────────────┐  │
│                                       │  Transport  │──┼──▶ Controller
│                                       │   Client    │  │
│                                       └─────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Files

| File | Purpose |
|------|---------|
| `cli.py` | Entry point, argument parsing, config loading |
| `sensor_controller.py` | Main orchestrator, lifecycle management |
| `capture_driver.py` | Monitor mode, channel hopping, frame capture |
| `frame_parser.py` | 802.11 parsing, IE extraction |
| `normalizer.py` | Telemetry normalization, OUI lookup |
| `risk.py` | Weighted risk scoring |
| `detection.py` | Evil twin, deauth detection |
| `buffer_manager.py` | Ring buffer, disk journal |
| `transport_client.py` | HTTP upload with retry |

---

## Quick Start

### Development Mode (No Hardware)

```bash
cd sensor
python cli.py --sensor-id dev-01 --iface mock0 --mock-mode
```

### Production Mode

```bash
cd sensor
sudo python cli.py --sensor-id prod-01 --iface wlan0 --config /etc/sentinel/config.yaml
```

---

## Configuration

See [Configuration Reference](../docs/getting-started/configuration.md) for full options.

Minimal `config.yaml`:

```yaml
sensor:
  id: "sensor-01"
  interface: "wlan0"

capture:
  channels: [1, 6, 11]
  dwell_ms: 200

transport:
  upload_url: "http://controller:5000/api/v1/telemetry"
```

---

## Testing

```bash
# Run unit tests
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=. --cov-report=html

# Specific test file
pytest tests/unit/test_frame_parser.py -v
```

---

## Dependencies

Core:
- `scapy` — Packet capture and parsing
- `requests` — HTTP client
- `pyyaml` — Configuration parsing
- `jsonschema` — Schema validation

Install:
```bash
pip install -r requirements.txt
```

---

## JSON Schemas

Telemetry output conforms to:
- [schema/telemetry.json](schema/telemetry.json) — Single record
- [schema/telemetry_batch.json](schema/telemetry_batch.json) — Batch upload

---

## Systemd Service

Production deployment uses systemd. See:
- [ops/systemd/sentinel-sensor.service](../ops/systemd/sentinel-sensor.service)
- [Production Deployment Guide](../docs/prod/deployment.md)
