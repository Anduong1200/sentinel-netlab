# Installation Guide (Ubuntu/Debian)

This guide covers the installation of Sentinel NetLab on Debian-based systems (Ubuntu 22.04+, Debian 12+, Kali Linux).

## Prerequisite Hardware

For detailed hardware specifications (CPU, RAM, OS Kernel, Storage) for both the Sensor and Controller across different deployment environments (including Virtual Machines), please refer to the **[Hardware & Software Requirements](../reference/hardware_requirements.md)** document.

---

## Part 1: System Dependencies

Update your system and install required build tools.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    python3 python3-pip python3-venv \
    libpcap-dev libpq-dev \
    build-essential git \
    wireless-tools iw tcpdump \
    gpsd gpsd-clients  # For Wardriving
```

If you plan to run the **Controller**:
```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and log back in for group changes to take effect
```

---

## Part 1B: Arch Linux + VMware (Sensor on VM)

If you are on **Windows 11** and want to run the **Sensor** inside a **VMware** Linux VM,
use an **Arch Linux** guest with USB passthrough for your WiFi adapter (e.g., TL-WN722N v1).

### A. VMware setup (host side)
1. Install VMware Workstation/Player.
2. Create an Arch Linux VM (2+ cores, 4GB+ RAM).
3. **Enable USB passthrough** and attach your WiFi adapter to the VM:
   - VM settings → USB Controller → Enable USB 2.0/3.0.
   - Run the VM, then attach the adapter: **VM > Removable Devices > Your WiFi Adapter > Connect (Disconnect from Host)**.

> Tip: If the adapter keeps reconnecting to Windows, disable Windows auto-driver handling or unplug/replug after VM is running.

### B. Arch Linux dependencies (guest side)
```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --needed --noconfirm \
  git base-devel make curl jq \
  python python-pip python-virtualenv \
  docker docker-compose

# Nếu bạn dùng capture thật (không mock), cài thêm:
sudo pacman -S --needed --noconfirm iw wireless_tools aircrack-ng tcpdump tshark gpsd
```

### C. Bật Docker đúng cách
```bash
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
docker info
docker compose version
```

### D. Verify adapter + monitor mode
```bash
lsusb
ip link
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
iw wlan0 info
```

### E. Continue with Part 2–4 below
Once monitor mode is working, follow **Part 2–4** to install dependencies and run the sensor.

---

## Part 2: Repository Setup

Clone the repository and set up the Python environment.

```bash
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Create Virtual Environment
python3 -m venv venv
source venv/bin/activate

### 3. Install Dependencies

We use `pyproject.toml` with optional dependencies ("extras") to keep installs lightweight.

**For Controller (Server):**
```bash
pip install ".[controller]"
```

**For Sensor (Node):**
```bash
pip install ".[sensor]"
```

**For Dashboard (UI):**
```bash
pip install ".[dashboard]"
```

**For Development (All tools):**
```bash
pip install ".[dev]"
```

---

## Part 3: Deploying the Controller

The controller manages sensors and aggregates data. It is best run via Docker.

1.  **Configure**:
    ```bash
    cp config.example.yaml config.yaml
    # Edit config.yaml to set SECRET_KEY and DB credentials if changing defaults
    ```

2.  **Start Services**:
    ```bash
    # Hardened production stack
    docker compose -f ops/docker-compose.prod.yml up -d
    ```

3.  **Verify**:
    - Dashboard: `http://<CONTROLLER_IP>:8050`
    - API: `http://<CONTROLLER_IP>:5000/api/v1/health`

---

## Part 4: Deploying a Sensor

Sensors are the eyes and ears. They run directly on hardware to access the WiFi card (Docker monitor mode can be tricky).

1.  **Put Interface in Monitor Mode**:
    Use `airmon-ng` (from aircrack-ng) or standard tools.
    ```bash
    sudo ip link set wlan1 down
    sudo iw wlan1 set type monitor
    sudo ip link set wlan1 up
    # Verify
    iw wlan1 info
    ```

2.  **Run the Sensor**:
    ```bash
    # Ensure you are in venv
    source venv/bin/activate

    # Install runtime dependencies if this is a fresh venv
    pip install -e .[sensor]
    
    # Run via legacy unified entry point (or use TUI: python -m sensor.tui)
    sudo ./venv/bin/python scripts/sentinel.py monitor \
        --sensor-id "sensor-01" \
        --iface wlan1 \
        --upload-url "http://<CONTROLLER_IP>:5000/api/v1/telemetry"
    ```
    *Note: `sudo` is required to control the network interface.*
    *If you prefer the terminal dashboard flow instead of raw CLI flags, see [`docs/lab/tui_guide.md`](../lab/tui_guide.md) and run `python -m sensor.tui`.*

3.  **Verify**:
    You should see logs indicating frames captured and batches uploaded.

---

## Troubleshooting

### "Operation not permitted" (Sensor)
Ensure you run with `sudo`. Typical valid WiFi operations need root.

### "No such device"
Check your interface name with `ip link` or `iwconfig`. It might be `wlan0`, `wlan1`, or `wlx...`.

### "Database connection failed" (Controller)
Ensure Docker containers are running (`docker ps`). Check if `postgres` is healthy.
```bash
docker compose -f ops/docker-compose.prod.yml logs postgres
```
