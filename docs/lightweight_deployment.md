# Lightweight Deployment Guide

> Deploy Sentinel NetLab Sensor with minimal resource usage.

## 📊 Deployment Options Comparison

| Option | RAM | Disk | Setup Time | Best For |
|--------|-----|------|------------|----------|
| **Debian VM (Full)** | 2-4GB | 20GB | 30 min | Learning/Demo |
| **Debian VM (Minimal)** | 180-300MB | 2GB | 15 min | Field work |
| **Docker (Debian)** | 200-300MB | 500MB | 5 min | Easy deployment |
| **Docker (Alpine)** | 60-100MB | 150MB | 5 min | Maximum efficiency |
| **Live USB** | 256MB | 0 (RAM) | 0 | Instant boot |

---

## 🐧 Option 1: Debian Minimal VM

Best for: **Production use, field assessments**

### Prerequisites
- VirtualBox/VMware
- Debian 12 "Netinst" ISO (~400MB)
- USB WiFi adapter (AR9271 recommended)

### Installation Steps

1. **Download Debian Netinst**
   ```
   https://www.debian.org/distrib/netinst
   ```

2. **Create VM**
   - RAM: 512MB - 1GB
   - Disk: 4GB (dynamic)
   - Network: NAT + Host-only
   - USB: Enable USB 3.0

3. **Install Debian (Minimal)**
   - Language: English
   - Hostname: `sentinel-sensor`
   - Root password: (set strong password)
   - Partitioning: Use entire disk
   - **Software selection**: 
     - ❌ Debian desktop environment
     - ❌ GNOME
     - ✅ SSH server
     - ✅ Standard system utilities

4. **Run Setup Script**
   ```bash
   # Copy script to VM
   scp scripts/setup_debian_minimal.sh user@vm-ip:/tmp/
   
   # SSH into VM
   ssh user@vm-ip
   
   # Run setup
   sudo bash /tmp/setup_debian_minimal.sh
   ```

5. **Copy Sensor Code**
   ```bash
   scp -r sensor/ user@vm-ip:/opt/sentinel-netlab/
   ```

6. **Start Sensor**
   ```bash
   sudo systemctl enable sentinel-sensor
   sudo systemctl start sentinel-sensor
   ```

### Verify Installation
```bash
# Check memory usage
free -h
# Expected: ~180MB used

# Check sensor
curl http://localhost:5000/health

# Check wireless
iw dev
```

---

## 🐳 Option 2: Docker Deployment

Best for: **Quick deployment, testing, CI/CD**

### Prerequisites
- Linux host with Docker
- USB WiFi adapter connected

### Alpine (Ultra-Light)

```bash
cd docker

# Build image
docker build -f Dockerfile.alpine -t sentinel-sensor:alpine ..

# Run container
docker run -d \
  --name sentinel \
  --privileged \
  --net=host \
  -e WIFI_SCANNER_INTERFACE=wlan0 \
  -e WIFI_SCANNER_API_KEY=your-secret-key \
  sentinel-sensor:alpine

# Check logs
docker logs -f sentinel

# Check status
curl http://localhost:5000/status
```

### Debian (Compatible)

```bash
cd docker

# Build image
docker build -f Dockerfile.debian -t sentinel-sensor:debian ..

# Run container
docker run -d \
  --name sentinel \
  --privileged \
  --net=host \
  -e WIFI_SCANNER_INTERFACE=wlan0 \
  sentinel-sensor:debian
```

### Docker Compose

```bash
cd docker

# Start Alpine sensor
docker compose up -d sensor-alpine

# Or start Debian sensor
docker compose --profile debian up -d sensor-debian

# View logs
docker compose logs -f

# Stop
docker compose down
```

### Docker on Windows (WSL2)

⚠️ **Important**: USB WiFi passthrough doesn't work in WSL2.

**Solution**: Run Docker inside the Linux VM instead:

```bash
# In your Debian/Kali VM
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Then run Docker commands as above
```

---

## 💾 Option 3: Live USB (Zero Install)

Best for: **Instant deployment, no trace left**

### Create Live USB

1. **Download Kali Linux Live**
   ```
   https://www.kali.org/get-kali/#kali-live
   ```

2. **Flash to USB**
   ```bash
   # Linux/Mac
   sudo dd if=kali-linux-live.iso of=/dev/sdX bs=4M status=progress
   
   # Windows: Use Rufus or Etcher
   ```

3. **Boot from USB**
   - Enter BIOS (F2/F12/Del)
   - Select USB boot

4. **Run Sensor**
   ```bash
   # After boot
   git clone https://github.com/your-repo/sentinel-netlab
   cd sentinel-netlab
   pip install -r sensor/requirements.txt
   cd sensor
   sudo python sensor_cli.py --engine tshark --api
   ```

### Persistence (Save Settings)

```bash
# Create persistence partition on USB
# During Kali boot, select "Live USB with Persistence"
```

---

## ⚙️ System Optimization Checklist

### Before Deployment

- [ ] Disable GUI (use server/minimal install)
- [ ] Disable Bluetooth service
- [ ] Disable CUPS (printing)
- [ ] Disable Avahi (mDNS)
- [ ] Set kernel parameters (sysctl)
- [ ] Use SSD or RAM disk for capture files

### Runtime Optimization

```bash
# Check memory
free -h

# Check CPU
top -bn1 | head -20

# Check disk I/O
iostat -x 1 5

# Check network buffers
sysctl net.core.rmem_max
```

### Recommended Kernel Parameters

```bash
# /etc/sysctl.d/99-sentinel.conf

# Increase network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000

# Reduce disk sync (better for capture)
vm.dirty_ratio = 60
vm.dirty_background_ratio = 30

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
```

---

## 🔍 Troubleshooting

### Docker: "Interface not found"

```bash
# Make sure to use --privileged and --net=host
docker run --privileged --net=host ...

# Check interface exists on host first
ip link show
iw dev
```

### VM: USB Not Passing Through

```bash
# VirtualBox: Install Extension Pack
# VMware: Enable "Automatically connect new USB devices"

# Check USB in VM
lsusb | grep -i wireless
```

### Low Memory: OOM Killer

```bash
# Reduce buffer sizes
python sensor_cli.py --buffer-size 50 --flush-interval 2

# Or use swap
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 📈 Resource Benchmarks

### Memory Usage by Configuration

| Configuration | Idle | Active Scan |
|---------------|------|-------------|
| Debian Full GUI | 800MB | 1.2GB |
| Debian Minimal | 150MB | 250MB |
| Docker Debian | 180MB | 280MB |
| Docker Alpine | 50MB | 100MB |

### Disk Usage

| Configuration | Base | + Captures (1hr) |
|---------------|------|------------------|
| Debian Full | 15GB | +500MB |
| Debian Minimal | 1.5GB | +500MB |
| Docker Debian | 500MB | +500MB |
| Docker Alpine | 150MB | +500MB |

---

## 🚀 Quick Start Commands

```bash
# === DOCKER (Fastest) ===
cd docker
docker compose up -d sensor-alpine
curl http://localhost:5000/status

# === DEBIAN VM ===
sudo bash scripts/setup_debian_minimal.sh
sudo systemctl start sentinel-sensor

# === MANUAL RUN ===
cd sensor
sudo python sensor_cli.py \
  --engine tshark \
  --buffered-storage \
  --watchdog \
  --api
```

---

*Last updated: January 2024*
