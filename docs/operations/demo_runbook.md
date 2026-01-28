# Demo Runbook

> Step-by-step guide for live demonstration of Sentinel NetLab

---

## Overview

| Duration | Audience | Prerequisites |
|----------|----------|---------------|
| 10-15 min | Technical reviewers | VM ready, USB adapter |

---

## Pre-Demo Checklist

### Hardware
- [ ] Laptop with VirtualBox/VMware installed
- [ ] USB WiFi adapter connected (AR9271)
- [ ] Power adapter plugged in

### Software
- [ ] Linux VM booted
- [ ] Sensor installed and tested
- [ ] Windows controller ready

### Environment
- [ ] Visible WiFi networks (3+ in range)
- [ ] Network use authorization (if in office)

---

## Demo Script

### Step 1: Environment Check (2 min)

```bash
# On Linux VM

# Check USB adapter
lsusb | grep -i wireless

# Check wireless interface
iw dev

# Verify driver
python3 scripts/check_driver.py
```

**Show:** USB device detected, wlan0 interface present

---

### Step 2: Start Sensor (2 min)

**Option A: Real Hardware**
```bash
source /opt/sentinel-netlab/venv/bin/activate
cd sensor
sudo python3 api_server.py
```

**Option B: Mock Mode (No Hardware)**
```bash
export WIFI_SCANNER_MOCK_MODE=true
cd sensor
python3 api_server.py
```

**Expected:** Server running on http://0.0.0.0:5000

---

### Step 3: Verify API (1 min)

```bash
# Health check
curl http://localhost:5000/health

# Scan networks
curl -H "X-API-Key: sentinel-dev-2024" http://localhost:5000/scan | jq
```

**Show:** JSON response with detected networks and risk scores

---

### Step 4: Launch Controller GUI (2 min)

```powershell
# On Windows host
cd D:\hod_lab\controller
python scanner_gui.py
```

**Demo Points:**
1. Enter VM IP address → Connect
2. Click "Start Scan" → Networks appear
3. Sort by Risk Score column
4. Click high-risk network → Show details panel
5. Highlight `explain` field showing why it's risky

---

### Step 5: Export Data (1 min)

1. Click "Export CSV" in GUI
2. Open file in Excel/Notepad
3. Show columns: ssid, bssid, risk_score, risk_level

---

### Step 6: Show Metrics (Optional, 2 min)

```bash
# Prometheus metrics
curl http://localhost:5000/metrics
```

**Show:** `scan_duration`, `networks_found`, `active_alerts`

---

## Troubleshooting

### "No networks found"

```bash
# Re-enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### "Connection refused"

```bash
# Check if sensor is running
ps aux | grep api_server

# Check firewall
sudo ufw status
```

### GUI won't connect

1. Verify VM IP: `ip addr show`
2. Check network mode: Host-Only or NAT with port forward
3. Ping from Windows: `ping 192.168.56.101`

---

## Key Metrics to Highlight

| Metric | Target | Meaning |
|--------|--------|---------|
| Networks Detected | ≥5 | System captures real environment |
| Scan Duration | <5s | Acceptable performance |
| Risk Score Accuracy | Matches expectations | Algorithm works correctly |

---

## Post-Demo

1. Stop sensor: `Ctrl+C`
2. Take questions
3. Share documentation links

---

*Good luck with your demo!*
