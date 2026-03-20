# PCAP Replay & Testing

Sentinel NetLab supports generating synthetic attack traffic and replaying PCAP files to simulate network events. This is extremely useful for testing detection algorithms without requiring physical WiFi hardware or executing live attacks.

## Overview

The `tests/data/generate_pcap.py` script acts as a mock attack generator. It creates synthetic 802.11 PCAP files containing both baseline (normal) traffic and various attack vectors. The `PcapCaptureDriver` can then mimic a live WiFi interface by reading these frames and feeding them into the Sensor Controller pipeline.

Together with `MockCaptureDriver`, this lets the replay pipeline run end-to-end in CI without requiring monitor mode or physical WiFi hardware. The repository exposes the same checks through `Makefile` targets so local validation and GitHub Actions stay aligned.

---

## 1. Generating Mock Attacks (Golden PCAPs)

Use the included generator script to create synthetic PCAPs for specific attack scenarios. The script uses Scapy to construct realistic 802.11 management frames (Beacons, Deauths, Probes, etc.).

### Usage

```bash
# Generate all scenarios (Default behavior)
python tests/data/generate_pcap.py --scenario all --output tests/data/golden_vectors.pcap

# Generate a specific attack scenario
python tests/data/generate_pcap.py --scenario beacon_flood --output tests/data/beacon_flood.pcap
```

### Supported Scenarios

| Scenario | Description |
| :--- | :--- |
| `normal` | Baseline traffic. Beacons and Probe Requests from a legitimate "Corporate_WiFi" AP (RSSI -60). |
| `evil_twin` | Rogue AP broadcasting "Corporate_WiFi" with a stronger signal (RSSI -30) to hijack clients. |
| `deauth` | Flood of Deauthentication frames (Reason 7) targeting a specific client. |
| `disassoc_flood` | High-rate flood of Disassociation frames (Reason 8) targeting a specific client. |
| `beacon_flood` | Massive generation of random Fake APs (random MACs and SSIDs) across different channels. |
| `karma` | Attacker instantly responds to victim Probe Requests, pretending to be the requested hidden/saved network. |
| `pmkid` | Rapid Authentication/Association sequence to capture EAPOL M1 frames (PMKID Harvesting). |
| `all` | Generates a single PCAP containing all of the above scenarios sequentially. |

---

## 2. Running Replay Tests

The integration test suite utilizes these generated PCAPs to verify that the detection logic in the `algos/` directory correctly identifies the threats.

```bash
# Run the full hardware-free replay regression suite
make test-replay

# Or run the scenario tests directly
pytest tests/integration/test_scenarios.py -v
```

For the strict typing gate used by CI on the replay/mock stack:

```bash
make typecheck-replay-strict
```

*(Note: Ensure you have generated the `golden_vectors.pcap` file before running the integration tests, or use the `MockCaptureDriver` depending on the test suite configuration.)*

---

## 3. Manual Replay (Development)

You can configure the Sentinel NetLab sensor to read directly from a generated PCAP file instead of a live network interface. This is done by modifying your `config.yaml`.

```yaml
capture:
  interface: "wlan0mon"
  driver: "pcap"  # Instructs the sensor to use the PCAP driver
  pcap_path: "tests/data/golden_vectors.pcap" # Path to your generated mock attack file
  realtime: true  # Simulates original frame timing instead of processing instantly
```

Then run the sensor:

```bash
# Ensure you are using the current CLI entry point
python sensor/cli.py --config-file config.yaml
```

When running in this mode, the sensor will process the synthetic frames exactly as if they were sniffed over the air, allowing you to observe the risk scoring and alert generation in real-time.

## 4. CI Usage

Each pull request can enforce the replay stack without hardware by running:

```bash
make ci-replay
```

This bundles:

- `ruff` linting for the replay/mock files
- `mypy --strict` on the replay/mock stack
- PCAP regression tests for `PcapCaptureDriver` and `MockCaptureDriver`
- `bandit` static security scanning
