# 🗺️ Sentinel NetLab Roadmap

This document outlines the strategic plan for the Sentinel NetLab project, focusing on improving documentation, deployment, testing, and user experience.

## 📅 Timeline

### Week 1: Scope & Documentation Foundation
*   [ ] **Complete README**: Add CI/CD badges, coverage reports, and a clear "Active Defense" warning.
*   [ ] **Project Governance**: Create `ROADMAP.md` (this file), `CODE_OF_CONDUCT.md`, and `CONTRIBUTING.md`.
*   [ ] **Scope Definition**: Clarify WIDS vs. WIPS boundaries in all intro docs.

### Week 2: Tutorial & Deployment
*   [ ] **Installation Guide**: Write a step-by-step "from scratch" install guide for Ubuntu/Debian.
*   [ ] **Docker Support**: Enhance `docker-compose.yml` for a one-click full-stack deployment (Sensor + Controller + Dashboard).
*   [ ] **Kubernetes**: Add example K8s manifests for scaling.

### Week 3-4: Core Architecture & Persistence
*   [ ] **Data Persistence**: Replace in-memory `TELEMETRY_BUFFER` with actual `PostgreSQL` / `TimescaleDB` integration in `api_server.py`.
*   [ ] **Sensor Integration**: Refactor `wardrive.py` and `audit.py` to use `TransportClient` and integrate with `SensorController`.
*   [ ] **Unified Risk Engine**: Merge `algos/risk.py` and `common/risk_engine.py` into a single source of truth.

### Week 5-6: Security & Hardening
*   [ ] **mTLS**: Implement Mutual TLS authentication between Sensor and Controller (update `transport_client.py` and `api_server.py`).
*   [ ] **Active Defense Safety**: Implement `SAFE_MODE` env vars and strict whitelisting for `attacks.py`.
*   [ ] **Token Persistence**: Store API tokens in DB/Redis instead of in-memory.

### Week 7: UX & Dashboard Polish
*   [ ] **UX Design**: create wireframes for improved dashboard navigation.
*   [ ] **Visuals**: Add heatmaps for signal strength and attack visualization.
*   [ ] **Walkthrough**: Add a "first-run" wizard or walkthrough in the UI.

### Week 8: Release v1.0
*   [ ] **Versioning**: Tag the release (v1.0.0) following Semantic Versioning.
*   [ ] **Changelog**: meaningful release notes highlighting features and breaking changes.
*   [ ] **Distribution**: Build and publish Docker images and Python wheels.

---

## 🛠️ Immediate Fixes (Priority)
*   [x] **Wardrive Upload**: `wardrive.py` now supports `--upload` to Controller.
*   [x] **Audit Integration**: `audit.py` can now return data for Controller ingestion.
*   [x] **Doc Clarity**: `README.md` now distinguishes between Tools and Platform mode.
*   [ ] **Database Connection**: Connect `api_server.py` to Postgres (Critical).

## 📊 Long-term Goals
*   **Edge Intelligence**: Move more detection logic to the sensor edge to reduce bandwidth.
*   **Plugin System**: Allow community contributions for new attack detection signatures.
*   **Cloud Integration**: Native support for AWS/Azure/GCP IoT core.
