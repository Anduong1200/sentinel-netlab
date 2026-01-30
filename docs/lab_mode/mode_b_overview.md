# Research Lab Mode (Mode B)

## Rationale
Sentinel NetLab is designed primarily for **education and research**. "Lab Mode" enables features that might be risky in a production defense context but are essential for studying attack behaviors.

## Capabilities
1. **Passive Monitoring**: Silent recording of 802.11 frames without transmitting.
2. **Attack Simulation**: (Optional) Ability to replay PCAP vectors for testing detection logic.
3. **Raw Capture**: Storing full PCAP headers/payloads for offline analysis (vs. metadata only).

## Risk Mitigation
In Lab Mode, strict guardrails are enforced to prevent accidental interference with non-lab networks.

- **Geofencing** (Proposed): Limit operation to specific GPS coordinates.
- **BSSID Whitelisting**: Only target approved BSSIDs for active tests.
- **Fail-Safe**: Hardware watchdog to kill process if "Keep-Alive" from controller is lost.

See [Guardrails](guardrails.md) for implementation details.
