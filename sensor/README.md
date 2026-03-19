# Sentinel NetLab — Sensor Module

Lightweight WiFi capture agent for distributed intrusion detection.

---

## Overview

The sensor module is a standalone capture agent designed to run on:
- Raspberry Pi (primary target)
- Linux virtual machines
- Any Linux host with compatible WiFi adapter

It captures 802.11 management frames, processes them locally, and uploads telemetry to a central controller. It supports real-time capture via `tshark` or `scapy`, and offline analysis via PCAP files.

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
│  │   Channel   │                      │    Rule     │  │
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
| `cli.py` / `sensor_cli.py` | Unified entry point and CLI for sensor |
| `sensor_controller.py` | Main orchestrator, lifecycle management |
| `capture_driver.py` | Abstract capture driver (Mock, Pcap, Scapy) |
| `capture_tshark.py` | High-performance tshark capture engine |
| `capture_queue.py` | Producer-consumer queue for frame processing |
| `frame_parser.py` | 802.11 parsing, IE extraction |
| `normalizer.py` | Telemetry normalization, OUI lookup |
| `rule_engine.py` | Pattern matching and heuristic rule engine |
| `buffer_manager.py` | Ring buffer and disk journal for telemetry |
| `transport.py` | HTTP upload with retry, circuit breaker, and signature |
| `audit.py` | Security audit CLI (compliance checking) |
| `wardrive.py` | GPS-correlated wardriving CLI |
| `geo_mapping.py` | Trilateration & heatmaps |
| `config.py` | Environment and YAML configuration mapping |

*(Note: Detection algorithms like `evil_twin.py`, `dos.py`, and `risk.py` live in the `algos/` directory at the project root.)*

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
sudo python cli.py --sensor-id prod-01 --iface wlan0mon --config config.yaml
```

---

## Configuration

See [Configuration Reference](../docs/getting-started/configuration.md) for full options.

The sensor uses `config.py` to map environment variables to a structured configuration.

Minimal `config.yaml`:

```yaml
sensor:
  id: "sensor-01"
  interface: "wlan0mon"

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
pytest tests/unit/test_sensor_queue.py -v
```

---

## Dependencies

Core:
- `scapy` — Packet capture and parsing
- `requests` — HTTP client
- `pyyaml` — Configuration parsing
- `jsonschema` — Schema validation
- `pydantic` — Data validation and settings management

Install:
```bash
pip install -r requirements.txt
# Or via project root:
pip install ".[sensor]"
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
