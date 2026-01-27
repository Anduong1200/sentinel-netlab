# OS & Kernel Optimization Guide

> Advanced configuration for Sentinel NetLab Sensors

This guide details how to tune the Linux environment for low-latency wireless packet capture.

---

## 1. Distribution Selection

| Distro | RAM Usage | Best For |
|--------|-----------|----------|
| **Debian 12 (Netinst)** | ~180 MB | **Recommended**. Stability & compatibility. |
| **Kali Linux** | ~300 MB | Quick prototyping (drivers pre-installed). |
| **Alpine Linux** | ~60 MB | Extreme resource constraints (requires manual driver compilation). |

---

## 2. Automated Tuning (Recommended)

The unified setup script (`scripts/setup_vm.sh`) handles basic dependency installation but does **not** apply aggressive kernel tuning by default to ensure stability.

To apply performance tuning, add the following to `/etc/sysctl.conf`:

```bash
# Increase network capture buffers (prevents packet drops)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000

# Optimize VM dirty pages (better for writing PCAPs to disk)
vm.dirty_ratio = 80
vm.dirty_background_ratio = 5
```

Apply changes:
```bash
sudo sysctl -p
```

---

## 3. Kernel Configuration

For production sensors, use Kernel **6.1+ LTS** or **6.6+ LTS**.

### Optional: Real-time Kernel
If compiling a custom kernel, enable:
- `CONFIG_HZ_1000=y` (High resolution timer)
- `CONFIG_PREEMPT=y` (Low-latency desktop)

---

## 4. Headless Optimization Checklist

- [ ] **Disable GUI**: Use `systemctl set-default multi-user.target`
- [ ] **Disable Bluetooth**: `systemctl disable bluetooth`
- [ ] **Disable Printing**: `systemctl disable cups`
- [ ] **Disable Unused Services**: Avahi, ModemManager

---

## 5. Deployment Hardware Tuning

### Raspberry Pi 4/5
- Use **USB 3.0** ports for the WiFi adapter.
- Overclocking is **not** recommended (stability > speed).
- Use a high-quality (Class A1/A2) SD card or USB SSD for PCAP storage.

### Virtual Machines
- **USB Controller**: Set to USB 3.0 (xHCI).
- **RAM**: Minimum 1GB recommended (512MB possible with swap).
- **Cores**: 2 vCPUs minimum.

---

*Verified for Sentinel NetLab v1.0*
