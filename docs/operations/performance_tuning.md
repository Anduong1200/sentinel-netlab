# Performance Tuning Guide

> Optimize Sentinel-NetLab for production environments.

## 📊 Performance Profiles

### Profile 1: Lab/Demo (Default)
```bash
python sensor_cli.py -i wlan0 --engine scapy
```
- CPU: ~50-100%
- Throughput: 100-500 pps
- Use: Learning, demos

### Profile 2: Field Work (Optimized)
```bash
python sensor_cli.py -i wlan0 \
  --engine tshark \
  --buffered-storage \
  --buffer-size 100 \
  --flush-interval 5
```
- CPU: ~10-30%
- Throughput: 2000-5000 pps
- Use: SME audits

### Profile 3: High-Traffic (Maximum)
```bash
python sensor_cli.py -i wlan0 \
  --engine tshark \
  --buffered-storage \
  --buffer-size 500 \
  --flush-interval 10 \
  --watchdog \
  --api
```
- CPU: ~20-40%
- Throughput: 5000-10000 pps
- Use: Enterprise, public venues

---

## 🔧 Component Tuning

### 1. Capture Engine Selection

| Engine | CPU Usage | Throughput | Stability |
|--------|-----------|------------|-----------|
| `scapy` | High (80-100%) | 100-500 pps | ⭐⭐⭐ |
| `tshark` | Low (5-15%) | 2000-5000 pps | ⭐⭐⭐⭐⭐ |
| `queue` (Producer-Consumer) | Medium (20-30%) | 5000-10000 pps | ⭐⭐⭐⭐ |

**Recommendation**: Use `tshark` for all production scenarios.

### 2. Storage Tuning

| Setting | Lab | Field | High-Traffic |
|---------|-----|-------|--------------|
| `buffer-size` | 50 | 100 | 500 |
| `flush-interval` | 2s | 5s | 10s |
| Storage Type | HDD OK | SSD | NVMe |

**SQLite Optimization**:
```python
# Add to storage_buffered.py
conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes
conn.execute("PRAGMA cache_size=10000")  # 10MB cache
```

### 3. Channel Hopping

| Setting | Coverage | Speed | Stability |
|---------|----------|-------|-----------|
| `1,6,11` | Basic 2.4GHz | Fast | ⭐⭐⭐⭐⭐ |
| `1,2,3,4,5,6,7,8,9,10,11,12,13` | Full 2.4GHz | Slow | ⭐⭐⭐ |
| `1,6,11,36,40,44,48` | 2.4 + 5GHz | Medium | ⭐⭐⭐⭐ |

**Dwell Time** (time on each channel):
- 0.25s: Fast scan, may miss devices
- 0.5s: Balanced (default)
- 1.0s: Thorough, slower coverage

---

## 📈 Bottleneck Diagnosis

### 1. CPU Bottleneck

**Symptoms**:
- `top` shows Python at 100%
- Packets dropped in logs
- Slow API responses

**Solutions**:
1. Switch to `tshark` engine
2. Increase buffer size
3. Reduce channel count

### 2. I/O Bottleneck

**Symptoms**:
- High `iowait` in `top`
- Database write errors
- Capture pauses

**Solutions**:
1. Enable buffered storage
2. Use SSD/NVMe
3. Increase flush interval

### 3. USB Bottleneck

**Symptoms**:
- USB disconnections
- "Device not found" errors
- Channel set failures

**Solutions**:
1. Use powered USB hub
2. Enable watchdog
3. Reduce injection rate

### 4. Memory Bottleneck

**Symptoms**:
- OOM killer
- Swap usage high
- Slow performance

**Solutions**:
1. Reduce queue size
2. Limit scan history
3. Increase VM RAM

---

## 🛠️ Linux VM Optimization

### Kernel Parameters

```bash
# /etc/sysctl.conf

# Increase network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Reduce disk sync frequency
vm.dirty_ratio = 60
vm.dirty_background_ratio = 30

# Apply
sudo sysctl -p
```

### Systemd Service Optimization

```ini
# /etc/systemd/system/wifi-scanner.service

[Service]
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=50
```

### Disable Unnecessary Services

```bash
# Disable GUI if not needed
sudo systemctl set-default multi-user.target

# Disable unwanted services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

---

## 📊 Monitoring & Metrics

### Real-time Monitoring

```bash
# Watch capture stats
watch -n1 'curl -s http://localhost:5000/status | jq'

# Monitor system resources
htop

# USB device status
watch -n2 'lsusb | grep -i wireless'
```

### Key Metrics to Track

| Metric | Good | Warning | Critical |
|--------|------|---------|----------|
| CPU Usage | <50% | 50-80% | >80% |
| Queue Size | <1000 | 1000-5000 | >5000 |
| Flush Interval | <5s | 5-15s | >15s |
| Packet Drop | 0% | <1% | >1% |

### Prometheus Metrics (Optional)

```python
# Add to sensor_cli.py
from prometheus_client import Counter, Gauge, start_http_server

packets_counter = Counter('packets_total', 'Total packets processed')
queue_size = Gauge('queue_size', 'Current queue size')
networks_found = Gauge('networks_total', 'Total networks discovered')

start_http_server(8000)  # Metrics on :8000/metrics
```

---

## 🔄 Benchmark Scripts

### Throughput Test

```bash
# Generate test traffic
sudo tshark -i wlan0 -w /dev/null -q &

# Count packets for 60 seconds
timeout 60 tcpdump -i wlan0 -q 2>/dev/null | wc -l
```

### Latency Test

```python
import time
import requests

times = []
for _ in range(100):
    start = time.time()
    requests.get("http://localhost:5000/networks")
    times.append(time.time() - start)

print(f"Avg: {sum(times)/len(times)*1000:.1f}ms")
print(f"Max: {max(times)*1000:.1f}ms")
```

### Stress Test

```bash
# Run for 1 hour, check stability
timeout 3600 python sensor_cli.py -i wlan0 \
  --engine tshark \
  --buffered-storage \
  --stats
```

---

## 📝 Performance Checklist

Before field deployment:

- [ ] Use `tshark` engine
- [ ] Enable buffered storage
- [ ] Set appropriate buffer size (100-500)
- [ ] Enable USB watchdog
- [ ] Use SSD storage
- [ ] Use AR9271 chipset
- [ ] Use powered USB hub
- [ ] Disable unnecessary VM services
- [ ] Test for 1+ hour stability
- [ ] Verify no packet drops

---

*Performance data based on testing with AR9271 chipset on 4-core VM.*
