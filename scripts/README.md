# Sentinel NetLab - Scripts Directory

Utility scripts for setup, maintenance, and operations.

## 📁 Contents

| Script | Purpose |
|--------|---------|
| `setup_vm.sh` | **Main** - Full VM setup with all dependencies |
| `setup_debian_minimal.sh` | Minimal Debian setup (~180MB RAM) |
| `install_service.sh` | Install systemd service |
| `check_driver.py` | Diagnose WiFi adapter issues |
| `calibrate_weights.py` | Calibrate risk scoring weights |
| `cleanup_project.py` | Clean temp files, setup directories |
| `rotate_pcap.sh` | Rotate PCAP capture files |
| `package_release.sh` | Build release package |
| `setup_host.ps1` | Windows host setup (PowerShell) |
| `entrypoint.sh` | Docker container entrypoint |

---

## 🚀 Quick Start

### Full VM Setup
```bash
sudo ./setup_vm.sh
```

### Install as System Service
```bash
sudo ./install_service.sh
```

### Check WiFi Driver
```bash
python3 check_driver.py
```

### Calibrate Risk Weights
```bash
python3 calibrate_weights.py --demo --validate
```

---

## 📋 Script Details

### setup_vm.sh
Complete setup for Debian/Ubuntu/Kali VM:
- Installs system packages (tshark, aircrack-ng, iw)
- Creates Python virtual environment
- Installs Python dependencies
- Configures permissions

### check_driver.py
Diagnostic tool that checks:
- USB devices (`lsusb`)
- Wireless interfaces (`iw dev`)
- Loaded kernel modules
- Firmware presence
- dmesg logs

### calibrate_weights.py
ML weight calibration:
```bash
# Demo mode with sample data
python3 calibrate_weights.py --demo --validate

# With real labeled data
python3 calibrate_weights.py labeled_data.json -o weights.json
```

---

*See [installation.md](../docs/getting-started/installation.md) for complete setup instructions.*
