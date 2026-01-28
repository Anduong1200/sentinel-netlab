# Product Roadmap

## Current Release: v1.1.0 "Guardian" (Jan 2026)
**Focus:** Core WIDS functionality, Stability, and Assessment Tools.

- [x] **Distributed Architecture**: Dockerized Controller & Sensor.
- [x] **Detection Engine**: Risk scoring, Evil Twin, DoS detection.
- [x] **Assessment Mode**: Wardriving with GPS support (NMEA).
- [x] **Dashboard**: Dash-based UI for real-time visualization.
- [x] **Safeguards**: Active Defense safety locks (`LabSafetyChecker`).

---

## v1.2.0 "Observer" (Planned Q2 2026)
**Focus:** Machine Learning & Advanced Analytics.

- [ ] **ML Anomaly Detection**:
  - [ ] Train Autoencoder on baseline traffic (PyTorch).
  - [ ] Deploy inference engine to sensors.
- [ ] **Data Retention Policy**:
  - [ ] Automated pruning of old PCAPs/logs.
- [ ] **Hardening**:
  - [ ] Mutual TLS (mTLS) for Sensor-Controller communication.
  - [ ] Role-Based Access Control (RBAC) for Dashboard.

---

## v2.0.0 "Sentinel" (Planned Q4 2026)
**Focus:** Enterprise Integration & Cloud.

- [ ] **Cloud Native**: Kubernetes (Helm Charts) deployment.
- [ ] **SIEM Integration**: Forward alerts to Splunk/ELK via Syslog/Webhooks.
- [ ] **Active Defense V2**:
  - [ ] Automated containment (e.g., switch port blocking via SDN integration).
  - [ ] Legal-compliance checks per jurisdiction.
- [ ] **Mobile App**: Companion app for field assessments.

---

## Backlog / Wishlist
- [ ] FPGA/SDR support for hardware acceleration.
- [ ] Bluetooth/BLE monitoring (Ubertooth integration).
- [ ] Zigbee/IoT analysis.
