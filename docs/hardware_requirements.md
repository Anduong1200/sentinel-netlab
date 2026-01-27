# Hardware Requirements & Recommendations

> Complete guide for hardware selection to maximize Sentinel-NetLab performance.

## 🎯 Quick Reference

| Component | Minimum | Recommended | Professional |
|-----------|---------|-------------|--------------|
| **WiFi Adapter** | Any AR9271 | Alfa AWUS036NHA | Alfa AWUS036ACH |
| **Host RAM** | 8GB | 16GB | 32GB |
| **VM RAM** | 2GB | 4GB | 8GB |
| **VM CPU Cores** | 2 | 4 | 4+ |
| **Storage** | HDD 20GB | SSD 50GB | NVMe 100GB+ |

---

## 📡 WiFi Adapter Selection (Critical)

The WiFi adapter is the **most important component**. Must support **Monitor Mode** and **Packet Injection**.

### Tier 1: Recommended (Best Linux Support)

| Model | Chipset | Band | Price | Notes |
|-------|---------|------|-------|-------|
| **TP-Link TL-WN722N v1** | AR9271 | 2.4GHz | $15-20 | ⚠️ Must be v1, NOT v2/v3 |
| **Alfa AWUS036NHA** | AR9271 | 2.4GHz | $25-35 | Most stable for pentesting |
| **Alfa AWUS036NH** | AR9271 | 2.4GHz | $30-40 | Higher power (2000mW) |

### Tier 2: Advanced (5GHz Support)

| Model | Chipset | Band | Price | Notes |
|-------|---------|------|-------|-------|
| **Alfa AWUS036ACH** | RTL8812AU | 2.4/5GHz | $50-70 | Requires driver install |
| **Alfa AWUS036ACHM** | MT7612U | 2.4/5GHz | $45-60 | Good AC support |
| **Panda PAU09** | RTL8814AU | 2.4/5GHz | $40-50 | Dual antenna |

### ⚠️ Avoid These Chipsets

| Chipset | Issue |
|---------|-------|
| **RTL8188** series | No monitor mode |
| **Intel AX200/201** | Limited injection |
| **Broadcom BCM43** | Driver issues on Linux |
| **TP-Link WN722N v2/v3** | Uses different chip (no monitor) |

### How to Verify Chipset

```bash
# Before buying, check if adapter supports monitor mode
lsusb  # Find vendor:product ID

# After connecting
iw list | grep -A10 "Supported interface modes"
# Should show "monitor" in the list
```

---

## 💻 Host System Requirements

### Minimum (Demo/Learning)

- **OS**: Windows 10/11 64-bit
- **CPU**: Intel Core i5 (4th gen+) or AMD Ryzen 3
- **RAM**: 8GB total (2GB for VM)
- **Storage**: 20GB free space (HDD acceptable)
- **USB**: USB 2.0 port

### Recommended (Field Work)

- **OS**: Windows 10/11 Pro
- **CPU**: Intel Core i7 (8th gen+) or AMD Ryzen 5
- **RAM**: 16GB total (4GB for VM)
- **Storage**: 50GB free on SSD
- **USB**: USB 3.0 port
- **Battery**: 6+ hours

### Professional (High-Traffic Environments)

- **OS**: Windows 11 Pro
- **CPU**: Intel Core i7/i9 (10th gen+) or AMD Ryzen 7
- **RAM**: 32GB total (8GB for VM)
- **Storage**: 100GB+ on NVMe SSD
- **USB**: USB 3.1/3.2 port with powered hub
- **Power**: AC adapter always connected

---

## 🖥️ Virtual Machine Configuration

### VirtualBox Settings

```
General:
  - Type: Linux
  - Version: Ubuntu 64-bit or Debian 64-bit

System:
  - Base Memory: 4096 MB
  - Processors: 4
  - Enable PAE/NX: ✓
  - Enable VT-x/AMD-V: ✓

Display:
  - Video Memory: 128 MB
  - Graphics Controller: VMSVGA

USB:
  - Enable USB Controller: ✓
  - USB 3.0 (xHCI) Controller: ✓
  - Add Filter for WiFi adapter
```

### VMware Workstation Settings

```
Hardware:
  - Memory: 4096 MB
  - Processors: 4 cores
  - USB Controller: Present (USB 3.0)

Options:
  - Guest Isolation > Drag and Drop: Disabled
  - USB Devices > Automatically connect new USB devices: ✓
```

---

## 🔌 USB Passthrough Best Practices

### Problem: USB Disconnection During Attacks

**Cause**: High power consumption during packet injection causes voltage drop.

**Solutions**:

1. **Powered USB Hub**: Use a hub with external power supply
2. **Direct Connection**: Connect to mainboard USB, not front panel
3. **USB 3.0**: Provides more power than 2.0
4. **Disable USB Suspend**: 
   ```powershell
   # Windows: Disable USB selective suspend
   powercfg -setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
   ```

### Problem: USB Latency in VM

**Cause**: Multiple abstraction layers (Host Driver → Hypervisor → Guest Driver).

**Solutions**:

1. **Use VirtualBox Extension Pack**: Enables USB 3.0
2. **Disable USB 1.1 Controller**: Only enable USB 3.0
3. **Pin USB to VM**: Use USB filter to auto-attach

---

## 📶 Antenna Recommendations

### Standard (Included)

- **Type**: Omni-directional
- **Gain**: 2-5 dBi
- **Range**: ~50m indoor
- **Use Case**: General scanning

### Extended Range

| Antenna | Gain | Range | Use Case |
|---------|------|-------|----------|
| 9dBi Omni | 9 dBi | ~100m | Office building scan |
| 12dBi Yagi | 12 dBi | ~200m | Directional (outdoor) |
| Panel | 14+ dBi | ~300m | Fixed location monitoring |

### Antenna Connector Types

- **RP-SMA**: Most common (Alfa, TP-Link)
- **SMA**: Less common
- Check compatibility before purchasing

---

## ⚡ Power Considerations

### Laptop Battery Impact

| Mode | Power Draw | Battery Life |
|------|------------|--------------|
| Idle VM | ~10W | 4-5 hours |
| Passive Scan | ~15W | 3-4 hours |
| Active Attack | ~20W | 2-3 hours |

### Recommendations for Field Work

1. **Always use AC power** during active attacks
2. Carry **USB power bank** as backup for adapter
3. Use **lightweight Linux distro** (Kali minimal, Alpine)
4. Configure **power profiles** to reduce VM overhead

---

## 🔧 Troubleshooting Hardware Issues

### USB Adapter Not Detected

```bash
# Check USB connection
lsusb | grep -i wireless

# Check kernel messages
dmesg | tail -20

# Load driver manually (AR9271)
sudo modprobe ath9k_htc
```

### Monitor Mode Fails

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable manually
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify
iw dev wlan0 info | grep type
```

### Packet Injection Fails

```bash
# Test injection
sudo aireplay-ng --test wlan0

# If fails, try:
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

---

## 📦 Recommended Purchase List

### Budget Setup (~$30)

- TP-Link TL-WN722N v1: $15
- USB 3.0 Extension Cable: $10
- Total: ~$25-30

### Standard Setup (~$80)

- Alfa AWUS036NHA: $30
- 9dBi Omni Antenna: $15
- Powered USB 3.0 Hub: $25
- USB Extension Cable: $10
- Total: ~$80

### Professional Setup (~$200)

- Alfa AWUS036ACH: $60
- Alfa AWUS036NHA (backup): $30
- 12dBi Yagi Antenna: $25
- 9dBi Omni Antenna: $15
- Powered USB 3.0 Hub: $25
- USB 3.0 Extension (5m): $20
- Pelican Case: $25
- Total: ~$200

---

## 📊 Performance Benchmarks

### Packets/Second by Hardware

| Configuration | Passive Scan | Active Attack |
|---------------|--------------|---------------|
| AR9271 + Scapy | 100-500 pps | 50-100 pps |
| AR9271 + tshark | 2000-5000 pps | 500-1000 pps |
| RTL8812AU + Scapy | 200-800 pps | 100-200 pps |
| RTL8812AU + tshark | 3000-8000 pps | 800-1500 pps |

### Bottleneck Analysis

1. **CPU** → Switch to tshark/dumpcap
2. **USB Latency** → Use USB 3.0 + direct connection
3. **Disk I/O** → Use SSD + buffered writes
4. **Driver Stability** → Use AR9271 chipset

---

*Last updated: January 2024*
