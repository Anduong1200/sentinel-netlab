# 🗺️ Sentinel NetLab Roadmap

This document outlines the strategic plan for the Sentinel NetLab project.

## ✅ Completed Milestones

### Documentation & Governance
*   [x] **Complete README**: CI/CD badges, coverage reports, and "Active Defense" warning
*   [x] **Project Governance**: `ROADMAP.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`
*   [x] **Scope Definition**: WIDS vs. WIPS boundaries clarified in all docs
*   [x] **Docs Reorganization**: Split into `docs/lab/` (Education) and `docs/prod/` (Deployment)

### Deployment & Infrastructure
*   [x] **Docker Support**: Full-stack `docker-compose.yml` (Sensor + Controller + Dashboard)
*   [x] **Lab Mode**: `make lab-up`, auto-generated secrets, `127.0.0.1`-only binding
*   [x] **Production Hardening**: Fail-fast config, TLS, HMAC, network segmentation
*   [x] **CI/CD Pipeline**: Lint, test, security scan (TruffleHog, Gitleaks, CodeQL, Trivy, Bandit)

### Core Architecture
*   [x] **Data Persistence**: PostgreSQL integration with Alembic migrations
*   [x] **Unified Risk Engine**: `algos/risk.py` as single source of truth
*   [x] **Sensor Integration**: `wardrive.py` and `audit.py` use `TransportClient`
*   [x] **Dashboard Refactor**: Multi-page architecture (overview, map, threats, signals)
*   [x] **Observability**: Structured JSON logging, Prometheus metrics, correlation IDs
*   [x] **PMKID Detector**: Dual-layer harvesting detection (Auth flood + EAPOL M1 orphan tracking)
*   [x] **Disassoc Flood Detector**: Sliding-window disassociation frame rate analysis with multi-client severity
*   [x] **Beacon Flood Detector**: Fake AP detection via SSID/BSSID diversity counting (mdk3/mdk4)
*   [x] **KRACK Detector**: Key Reinstallation Attack — EAPOL M3 replay detection (CVE-2017-13077)
*   [x] **Detector Pipeline**: All 11 detectors wired into `sensor_controller.py` capture loop

### Quality & Reliability
*   [x] **Release Audit**: 5 passes, 45 bugs fixed (5 critical operational bugs)
*   [x] **Scalability**: Bulk ingest, DB indexing/partitioning
*   [x] **CI Vulnerability Fixes**: Trivy-detected issues in Docker images resolved
*   [x] **159 Unit Tests**: Comprehensive coverage across all detectors and components

---

## 📅 Upcoming Work

### Short-term
*   [ ] **Kubernetes**: Add example K8s manifests for horizontal sensor scaling
*   [ ] **mTLS**: Implement Mutual TLS authentication between Sensor and Controller
*   [ ] **Token Persistence**: Store API tokens in DB/Redis instead of in-memory

### Medium-term
*   [ ] **UX Polish**: Improved dashboard navigation, first-run wizard
*   [ ] **Heatmaps**: Enhanced signal strength and attack geo-visualization
*   [ ] **Distribution**: Build and publish Docker images and Python wheels

---

## 📊 Long-term Goals
*   **Edge Intelligence**: Move more detection logic to the sensor edge to reduce bandwidth.
*   **Plugin System**: Allow community contributions for new attack detection signatures.
*   **Cloud Integration**: Native support for AWS/Azure/GCP IoT core.
