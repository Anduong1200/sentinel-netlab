# Release Notes - v1.0.0 "Guardian"

**Date:** January 28, 2026
**Version:** 1.0.0
**Codename:** Guardian

---

## 🚀 Overview

We are proud to announce the first major release of **Sentinel NetLab**, a lightweight Hybrid Wireless Intrusion Detection System (WIDS). This release focuses on providing a comprehensive security assessment platform for resource-constrained environments (Raspberry Pi/IoT).

## ✨ Key Features

### 📡 Core Sensor Architecture
- **Hybrid Capture Engine**: Supports both `scapy` (native Python) and `tshark` (performance) backends.
- **Unified Telemetry Schema**: Standardized JSON format for all 802.11 management frames.
- **Robust Parsing**: Advanced parsing for Beacons, Probe Requests, Authentication, and Deauth frames.
- **Monitor Mode Automation**: Automatic interface configuration and channel hopping.

### 🛡️ WIDS & Threat Detection
- **Risk Scoring Engine v2**: Weighted multi-factor scoring (Encryption, RSSI, Vendor, Behavior) with explainability.
- **Attacks Detected**:
  - **Evil Twin**: Duplicate SSID detection with RSSI/BSSID discrepancy analysis.
  - **Deauth Flood**: Volume-based denial-of-service detection.
  - **Cipher Downgrade**: Detection of weak encryption advertisement.
  - **WPS Vulnerabilities**: Passive detection of WPS-enabled APs.

### 🗺️ Geo-Location & Mapping (New)
- **Trilateration**: Estimation of signal source using Log-Distance Path Loss model.
- **Heatmaps**: Generation of PNG/SVG coverage maps from multi-sensor data.
- **Kalman Filtering**: Noise reduction for stable position tracking.

### 🚗 Wardriving & Audit Kit
- **Wardrive CLI** (`wardrive.py`): GPS-correlated network scanning and mapping.
- **Security Audit** (`audit.py`): Automated checklist for home/SME deployment.
- **Consent-First Design**: Strict safety checks and ethical guidelines (`ETHICS.md`).

### ⚔️ Active Defense (Lab Only)
- **Attack Simulation**: Controlled Deauth and FakeAP generation for red-team training.
- **Safety Interlocks**: Requires environment variable overlaps to prevent accidental use.

## 🛠️ Technical Improvements
- **CI/CD Pipeline**: GitHub Actions for Linting (Ruff/Flake8), Unit Tests, and Build.
- **Code Quality**: 100% compliant with PEP8 (Flake8 verified).
- **Build System**: Standardized `pyproject.toml` configuration.
- **Documentation**: Complete architectural reference and system design specs.

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Install dependencies (Production)
pip install .

# Install for Development
pip install -e ".[dev]"
```

## ⚠️ Known Issues
- Active Defense modules are restricted to Lab environments by default.
- Geo-mapping accuracy depends on environment calibration (path loss exponent).

---

**Contributors:** Sentinel NetLab Team
**License:** MIT
