# Installation Guide (Ubuntu/Debian)

This guide covers the installation of Sentinel NetLab on Debian-based systems (Ubuntu 22.04+, Debian 12+, Kali Linux).

## Prerequisite Hardware

### Controller (Server)
- **CPU**: 2+ Cores
- **RAM**: 4GB+ (8GB recommended for heavy ELK usage)
- **Storage**: 20GB+
- **OS**: Ubuntu Server 22.04 LTS

### Sensor (Agent)
- **Device**: Raspberry Pi 4 (recommended) or any Linux laptop
- **WiFi Adapter**: Must support **Monitor Mode** and **Packet Injection**.
    - Recommended Chipsets:
        - `Atheros AR9271` (Alfa AWUS036NHA) - Rock solid
        - `MediaTek MT7612U` (Alfa AWUS036ACM) - Good 5GHz support
        - `RTL8812AU` - Common, but requires messy drivers
- **OS**: Raspberry Pi OS (64-bit) or Ubuntu/Kali

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

## Part 2: Repository Setup

Clone the repository and set up the Python environment.

```bash
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Create Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install --upgrade pip
pip install -e .
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
    make docker-up
    # Or manually: cd ops && docker-compose up -d
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
    
    # Run
    sudo env PATH=$PATH python sentinel.py monitor \
        --sensor-id "sensor-01" \
        --iface wlan1 \
        --upload-url "http://<CONTROLLER_IP>:5000/api/v1/telemetry"
    ```
    *Note: `sudo` is required to control the network interface.*

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
cd ops
docker-compose logs postgres
```
