# Sentinel NetLab v1.0.0 - Release Notes

## Overview
Sentinel NetLab v1.0.0 is the first integrated release of the hybrid Wireless Intrusion Detection System (WIDS). This release unifies the Controller, Sensor, and Dashboard into a cohesive platform suitable for academic and lab environments.

## Key Features

### Core Operations
-   **Centralized Controller**: Refactored `controller` with strict configuration validation (`controller/config.py`).
-   **Unified Sensor CLI**: `sentinel-sensor` entry point consolidates wardriving and WIDS/monitoring modes (`scripts/entrypoint.py`).
-   **Secure Communication**: All API endpoints use strictly typed schemas (`common/schemas`) and enforce role-based access control.

### Security
-   **Secrets Management**: Production-grade secret handling via `python-dotenv` and environment variables. Fails safe if secrets are missing.
-   **CI/CD Pipeline**: Robust GitHub Actions workflow (`ci.yml`) including:
    -   Static Analysis (Ruff, Mypy)
    -   Security Scanning (Bandit)
    -   Automated Testing (Pytest)
    -   Docker Build & Push
-   **Audit**: Complete codebase audit with zero High-severity vulnerabilities (Bandit/Ruff verified).

### Dashboard & Analytics
-   **Operational Panels**: Real-time Sensor Health status and connection metrics.
-   **Security Analytics**: Visualization of network security posture (Open vs WEP vs WPA2/3).
-   **Threat Intelligence**: Integrated alerting and reporting pipeline.

## Deployment
-   **Docker**: Optimized multi-stage builds for Controller, Sensor, and Dashboard.
-   **Local Dev**: Simplified setup with `ops/docker-compose.yml` and pre-configured `.env` template.

## Known Issues
-   **Simulation**: WIPS attacks (Deauth) are simulated in `dry-run` mode by default to prevent accidental interference.
-   **Driver**: Hardware capture requires a compatible monitor-mode interface; `mock_capture` is enabled by default for testing.
