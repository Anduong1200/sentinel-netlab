# OS & Kernel Optimization Guide

> Advanced configuration for Sentinel NetLab Sensors

This guide details how to tune the Linux environment for low-latency wireless packet capture and optimal resource usage.

---

## 1. Distribution Selection

### Why "Lightweight" Matters
Running a full desktop OS (Kali/Ubuntu Desktop) wastes ~2GB RAM on GUI rendering. A headless sensor performs better on limited hardware (e.g., Raspberry Pi, VM with USB passthrough).

### Comparison Matrix

| Distro | RAM Usage | Setup | Use Case |
|--------|-----------|-------|----------|
| **Debian 12 (Netinst)** | ~180 MB | Easy (apt) | **Recommended** for stability |
| **Alpine Linux** | ~50 MB | Advanced (apk) | Extreme resource constraints |
| **Kali "Barebone"** | ~300 MB | Medium | If pre-patched drivers needed |

---

## 2. Kernel Tuning

The Linux Kernel is the heart of packet capture. Default kernels are tuned for throughput (Servers) or responsiveness (Desktops), not necessarily real-time packet processing.

### Recommended Version
- **Version**: 6.1 LTS or 6.6 LTS (Best driver support for Atheros/Realtek)
- **Avoid**: Bleeding edge (driver instability) or very old (<5.15) kernels.

### Advanced Compilation (Optional)
If compiling a custom kernel, enable:

1.  **Timer Frequency**: `1000 HZ`
    - *Why*: Increases timestamp precision for captured frames.
    - *Config*: `CONFIG_HZ_1000=y`

2.  **Preemption Model**: `Low-Latency Desktop`
    - *Why*: Allows the kernel to interrupt tasks faster, reducing packet drops during bursts.
    - *Config*: `CONFIG_PREEMPT=y`

3.  **In-Kernel Drivers**:
    - Build `ath9k` or `rt2800usb` directly into the kernel (not as modules) for marginally faster load times.

---

## 3. System Optimization

### Headless Operation
- **Remove GUI**: Do not install GNOME/KDE.
- **Management**: Use SSH exclusively.

### Init System
- **Systemd**: Standard, easier to manage service dependencies.
- **OpenRC/Runit**: Lighter alternatives (for Alpine/Void), saves ~20-50MB RAM.

### Python Optimization
- **PyInstaller/Nuitka**: Compile Python code to binary to reduce startup time and dependence on system libraries.
- **Virtualenv**: Keep dependencies isolated (already implemented in setup scripts).

---

## 4. Implementation Roadmap

### Phase 1: Debian Minimal (Current Standard)
1. Install **Debian 12 Netinst**.
2. Select only **"SSH server"** and **"Standard system utilities"**.
3. Install capture stack:
   ```bash
   apt install python3 python3-pip tshark aircrack-ng wireless-tools firmware-atheros
   ```
4. Result: ~180MB RAM usage.

### Phase 2: Kernel Tuning (Performance)
Apply sysctl params (automated in `setup_debian_minimal.sh`):
```bash
# Increase buffer sizes to prevent packet loss
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

### Phase 3: "Hardcore" (Alpine/Custom)
For specialized hardware (e.g., embedded implants):
1. Use Alpine Linux.
2. Compile custom kernel with `CONFIG_HZ_1000`.
3. Strip all unused drivers (USB Audio, Printer, etc.).

---

## 5. Deployment Checklist

- [ ] **Distro**: Debian 12 Netinst / Ubuntu Server
- [ ] **Kernel**: 6.1+ LTS
- [ ] **GUI**: Disabled (Headless)
- [ ] **Firmware**: `firmware-atheros` installed
- [ ] **Tuning**: Network buffers increased via sysctl
- [ ] **Power**: USB autosuspend disabled (kernel boot param `usbcore.autosuspend=-1`)

---
*Based on performance analysis for Sentinel NetLab*
