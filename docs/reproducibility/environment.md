# Environment Specification

## Hardware Requirements (Sensor)
- **Device**: Raspberry Pi 4 Model B (4GB RAM recommended) or x86_64 VM.
- **Network Interface**:
    - Primary: Ethernet or Onboard WiFi (Management).
    - Secondary: USB WiFi Adapter with **Monitor Mode** support (Packet Injection optional but useful for active tests).
    - *Recommended Chipsets*: Atheros AR9271, Realtek RTL8812AU.

## Software Requirements
- **OS**: Linux (Kernel 5.10+). Windows supported for Controller dev only (Sensors require Linux network stack).
- **Runtime**: Python 3.11+.
- **Containerization**: Docker Engine 24+ & Docker Compose v2.

## Network Topology
- **Management VLAN**: Isolated subnet for Sensor <-> Controller communication (HTTPS).
- **Target VLAN**: The wireless network being monitored.
- **Airgap**: Sensors should NOT have direct internet access; only access to Controller VIP.
