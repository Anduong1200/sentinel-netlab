# Lightweight Deployment Guide

> Deploy Sentinel NetLab Sensor on minimal infrastructure.

## 📊 Deployment Matrix

| Option | RAM | Disk | Setup Time | Best For |
|--------|-----|------|------------|----------|
| **Debian VM (Minimal)** | 256MB | 2GB | 10 min | **Production / Field** |
| **Docker (Alpine)** | 80MB | 200MB | 2 min | CI/CD / Container Ops |
| **Live USB** | 512MB | 0 (RAM) | 5 min | Forensic / Non-persistent |

---

## 🐧 Option 1: Debian Minimal (Recommended)

### 1. Requirements
- Debian 12 (Netinst) or Ubuntu Server 22.04
- Root access
- Internet connection during setup

### 2. Installation Steps

**Step A: Base System**
Install Debian with only "SSH server" and "Standard system utilities".

**Step B: Automated Setup**
Copy the project to the sensor machine:
```bash
# On your host machine
scp -r sentinel-netlab user@sensor-ip:~
```

SSH into the sensor and run the unified setup:
```bash
ssh user@sensor-ip
cd sentinel-netlab

# Run the unified setup wizard
sudo ./scripts/setup_vm.sh
```

**Step C: Start Service**
```bash
# Copy service file (if not done automatically)
sudo cp sensor/wifi-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-scanner
```

### 3. Verification
```bash
curl http://localhost:5000/health
# {"status": "ok", ...}
```

---

## 🐳 Option 2: Docker Deployment

Ideal for testing or when you cannot modify host packages.

### 1. Build Image (Alpine)
```bash
cd docker
docker build -f Dockerfile.alpine -t sentinel-sensor:alpine ..
```

### 2. Run Container
⚠️ **Critical**: Must use `--net=host` and `--privileged` for WiFi monitor mode access.

```bash
docker run -d \
  --name sentinel \
  --privileged \
  --net=host \
  -v /var/lib/wifi-scanner:/var/lib/wifi-scanner \
  sentinel-sensor:alpine
```

### 3. Check Logs
```bash
docker logs -f sentinel
```

---

## 💾 Option 3: Performance Tuning for Low-Spec Hardware

If running on <512MB RAM (e.g., Pi Zero 2):

1. **Enable Swap**:
   ```bash
   sudo fallocate -l 1G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

2. **Tune Buffers** (in `sensor/config.py` or env vars):
   - Set `pcap_enabled = False` (saves disk IO)
   - Reduce `dwell_time` to 0.2s

---

## 🔍 Troubleshooting

### "Interface not found" in Docker
- Ensure the host OS has the driver installed and loaded.
- Verify `iw dev` on host shows the interface.
- Ensure `--net=host` is used.

### "Read-only file system"
- The sensor attempts to write PCAPs. Ensure you volume mount `/var/lib/wifi-scanner` if persistent storage is needed.

### "Device busy"
- Stop `NetworkManager` or `wpa_supplicant` on the interface before starting the sensor, or let the sensor kill interfering processes (default behavior).

---
