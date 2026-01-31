# PCAP Replay & Testing

Sentinel NetLab supports replaying PCAP files to simulate network traffic for testing detection logic without physical hardware.

## Overview

The `PcapCaptureDriver` mimics a live WiFi interface by reading frames from a file and feeding them into the Sensor Controller.

## 1. Generating Test Data
Use the included generator to create synthetic PCAPs for specific scenarios.

```bash
# Generate all scenarios (Normal, Evil Twin, Deauth)
python tests/data/generate_pcap.py --scenario all --output tests/data/golden.pcap

# Generate specific scenario
python tests/data/generate_pcap.py --scenario evil_twin --output tests/data/evil_twin.pcap
```

### Scenarios
- **Normal**: Beacons and Probe Requests from a legitimate "Corporate_WiFi" AP.
- **Evil Twin**: Rogue AP broadcasting "Corporate_WiFi" with stronger signal (RSSI -30 vs -60).
- **Deauth**: Flood of Deauthentication frames targeting a client.

## 2. Running Replay Tests
Use the integration test suite to verify detection logic.

```bash
# Run all scenario tests
pytest tests/integration/test_scenarios.py -v
```

## 3. Manual Replay (Development)
You can configure the sensor to use a PCAP file directly in `config.yaml`.

```yaml
capture:
  interface: "mon0"
  driver: "pcap"  # Use PCAP driver
  pcap_path: "tests/data/golden.pcap"
  realtime: true  # Simulate real-time timing
```

Then run the sensor:
```bash
python sensor/cli.py --config config.yaml
```
