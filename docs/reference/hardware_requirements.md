# Hardware & Software Requirements

Sentinel NetLab is a distributed application that can run on a single machine (All-in-One) or across multiple devices (Controller + Sensors).

## 🖥️ Controller & Dashboard (Server component)

The Controller handles data aggregation, database storage, risk scoring, and serves the Web Dashboard.

### Minimum Requirements (Lab / Learning Mode)
- **CPU:** 2 Cores
- **RAM:** 2 GB (4 GB recommended if running via Docker)
- **Storage:** 10 GB (SSD preferred)
- **OS Kernel:** Linux (Ubuntu 22.04+, Debian 12+) or Windows 11 / macOS (Docker Desktop required)
- **Network:** Localhost (127.0.0.1) access only

*Note on Virtual Machines:* If running the Controller in a VM (like VMware or VirtualBox), allocate at least 2 Cores and 4 GB RAM. Using a headless Linux server (without GNOME/desktop GUI) saves ~1.5GB RAM.

### Recommended Requirements (Production / Continuous Monitoring)
- **CPU:** 4+ Cores (Required for high-traffic environments and Machine Learning pipelines)
- **RAM:** 8+ GB
- **Storage:** 30+ GB SSD (For PostreSQL and telemetry retention)
- **OS Kernel:** Linux Server (Ubuntu 22.04 LTS recommended)
- **Network:** Dedicated LAN IP, Port 80/443 exposed via Reverse Proxy

---

## 📡 Sensor (Agent component)

The Sensor is responsible for capturing 802.11 management frames and uploading telemetry to the Controller.

### Hardware Requirements
- **Device:** Raspberry Pi 4/5, ordinary PC, or Laptop.
- **CPU:** 1 Core (ARM64 or x86_64)
- **RAM:** 512 MB minimum (1 GB recommended)
- **Storage:** 4 GB (MicroSD for RPi is sufficient)
- **WiFi Adapter:** Must support **Monitor Mode** and **Packet Injection**.
  - **Supported Chipsets (Linux):** Atheros AR9271, Ralink RT3070, MediaTek MT7612U, Realtek RTL8812AU (requires custom driver).
  - *Note:* Built-in laptop WiFi cards often do NOT support Monitor Mode reliably. An external USB WiFi Adapter is highly recommended.

### Software Requirements
- **OS Kernel:** **Linux only**. Bắt buộc dùng Linux (Requires Linux kernel >= 5.4, e.g., Kali Linux, Ubuntu, Debian, Arch).
- **Driver:** A valid `cfg80211` / `mac80211` compatible driver.
- Windows/macOS are **not supported** for running the Sensor natively due to OS-level restrictions on WiFi monitor mode.

#### ⚠️ Running Sensor in a Virtual Machine (Windows/macOS Host)
If you must run the Sensor inside a VM (e.g., VMware Workstation, VirtualBox on Windows 11):
1. You **must** use an external USB WiFi Adapter.
2. Enable **USB Passthrough** in your VM settings to attach the USB WiFi Adapter directly to the Linux guest OS.
3. The guest OS (Ubuntu/Arch/Kali) will recognize the adapter via `lsusb` and `ip link`.

---

## 🚀 Recommended Architectures

### 1. Developer / Student (All-in-One VM)
- **Host:** Windows 11 PC (16GB RAM)
- **VM Software:** VMware Workstation Player
- **Guest VM:** Ubuntu 22.04 Server (Allocated: 2 Cores, 4GB RAM, 20GB Disk)
- **Hardware Config:** USB WiFi Adapter (AR9271) connected via USB Passthrough to the VM.
- **Deployment:** Sensor + Controller running together inside the VM via `make lab-up`.

### 2. Distributed Sensor Network (Production)
- **Controller:** Cloud VPS or Dedicated Server (4 Cores, 8GB RAM, 50GB SSD, Ubuntu 22.04).
- **Sensors:** 3x Raspberry Pi 4s (2GB RAM) deployed physically across the building.
- **Sensors Hardware:** Alfa AWUS036ACM (MT7612U) plugged into each Raspberry Pi.
- **Network:** Sensors communicate with the Controller via HTTPS API over the building's Ethernet/WiFi.
