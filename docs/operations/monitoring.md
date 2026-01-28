# Metrics & Benchmarking Guide

> Complete guide for measuring and evaluating Sentinel NetLab performance

---

## 📊 Key Performance Indicators (KPIs)

### 1. Coverage & Detection

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **AP Detected** | Number of unique APs found | `curl /networks \| jq '.networks \| length'` |
| **Recall** | TP / (TP + FN) | `compare_recall.py` vs airodump-ng |
| **Precision** | TP / (TP + FP) | `compare_recall.py` vs airodump-ng |
| **F1 Score** | Harmonic mean of P & R | Calculated from above |

### 2. Latency & Timing

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **RTT API** | Request → Response time | `test_latency.py -n 50` |
| **Time-to-Display** | Capture end → GUI shows | Stopwatch or instrumented |
| **Time-to-Detect Rogue** | Rogue appears → Alert fired | Create fake AP, measure |

### 3. Packet Quality

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **Packet Loss** | % frames missed vs ground truth | Compare frame counts |
| **FPS** | Frames per second captured | `tshark` stats |

### 4. Resources & Stability

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **CPU %** | Sensor CPU usage | `htop`, `psutil` |
| **RAM (MB)** | Sensor memory usage | `htop`, `psutil` |
| **Uptime** | % time operational | `test_stability.py` |
| **MTTR** | Mean Time To Recovery | Measure restart time |
| **Crash Rate** | Crashes per day/week | Log analysis |

### 5. Data Quality

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **RSSI Accuracy** | dB error vs reference | Compare with WiFi Analyzer app |
| **Encryption Detection** | % correctly identified | Manual verification |
| **Risk Score Agreement** | vs expert labeling | Expert review |

### 6. Forensics

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **PCAP Integrity** | Opens in Wireshark | Manual check |
| **Storage Rate** | GB per day | `du -sh` |

---

## 🎯 Target Thresholds by Scale

| Metric | Big Tech | SME | Personal/Lab |
|--------|----------|-----|--------------|
| **Recall** | ≥ 90% | ≥ 80% | ≥ 70% |
| **Precision** | ≥ 95% | ≥ 90% | ≥ 85% |
| **RTT API (avg)** | < 500ms | < 1s | < 2s |
| **Time-to-Display** | < 2s | < 5s | < 8s |
| **Packet Loss** | < 5% | < 10% | < 15% |
| **CPU (sensor)** | < 50% | < 70% | < 80% |
| **Uptime** | 99.9% | 99% | 95% |
| **PCAP Retention** | 90+ days | 30-90 days | 7-30 days |

---

## 🧪 Test Procedures

### Quick Test (5 min)

```bash
# 1. Health check
curl http://localhost:5000/health

# 2. Get networks
curl http://localhost:5000/networks > poc.json

# 3. Quick latency
python tests/test_latency.py -n 10

# 4. Check resources
htop
```

### Standard Test (30 min)

```bash
# 1. Run ground truth (60s)
sudo timeout 60 airodump-ng wlan0 -w gt --output-format csv

# 2. Run PoC simultaneously
curl http://localhost:5000/networks > poc.json

# 3. Compare recall
python tests/compare_recall.py gt-01.csv poc.json

# 4. Latency test (50 requests)
python tests/test_latency.py -n 50

# 5. Stability test (30 min)
python tests/test_stability.py -d 30
```

### Comprehensive Test (2+ hours)

```bash
# Run full benchmark suite
python tests/benchmark_suite.py \
    --all \
    --gt-csv artifacts/gt.csv \
    --poc-json artifacts/poc.json \
    --duration 60 \
    --output benchmark_results
```

---

## 📈 Benchmark Commands

### Detection & Recall

```bash
# Generate ground truth (airodump-ng)
sudo airodump-ng wlan0 -w gt --output-format csv &
sleep 60
kill %1
mv gt-01.csv artifacts/gt_output.csv

# Get PoC output
curl -s http://localhost:5000/networks > artifacts/poc.json

# Compare
python tests/compare_recall.py \
    artifacts/gt_output.csv \
    artifacts/poc.json \
    -o artifacts/recall_report.txt
```

### Latency

```bash
# Basic latency test
python tests/test_latency.py --url http://localhost:5000 -n 50

# With API key
python tests/test_latency.py --api-key YOUR_KEY -n 100

# Test specific endpoints
python tests/test_latency.py --endpoints /health /status /networks
```

### Stability

```bash
# 30-minute test with 2-min intervals
python tests/test_stability.py -d 30 -i 2

# Long-running test (2 hours)
python tests/test_stability.py -d 120 -i 5
```

### Resources

```bash
# Monitor during test
watch -n1 'ps aux | grep python | head -5'

# Detailed with psutil
python -c "
import psutil
for p in psutil.process_iter(['name', 'cpu_percent', 'memory_info']):
    if 'python' in p.info['name'].lower():
        print(f\"{p.info['name']}: CPU={p.info['cpu_percent']}%, RAM={p.info['memory_info'].rss/1024/1024:.0f}MB\")
"
```

### PCAP Quality

```bash
# Verify PCAP opens in tshark
tshark -r artifacts/sample.pcap -c 10

# Count management frames
tshark -r artifacts/sample.pcap -Y "wlan.fc.type == 0" | wc -l

# Check timestamps
tshark -r artifacts/sample.pcap -T fields -e frame.time_epoch -c 5
```

---

## 📊 Reporting Template

### Summary Table

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| Recall | ≥80% | ___% | ✅/❌ |
| Precision | ≥90% | ___% | ✅/❌ |
| RTT (avg) | <1s | ___ms | ✅/❌ |
| Packet Loss | <10% | ___% | ✅/❌ |
| CPU (avg) | <70% | ___% | ✅/❌ |
| Uptime | 99% | ___% | ✅/❌ |

### Detailed Results

```
Detection:
  - APs Found: ___
  - SSIDs Found: ___
  - Hidden Networks: ___

Recall Analysis:
  - Ground Truth: ___ APs
  - Detected: ___ APs
  - True Positives: ___
  - False Positives: ___
  - False Negatives: ___
  - Recall: ___%
  - Precision: ___%

Latency:
  - /health: avg=___ms, p95=___ms
  - /status: avg=___ms, p95=___ms
  - /networks: avg=___ms, p95=___ms

Resources:
  - CPU (avg): ___%
  - RAM (avg): ___MB
  - Test Duration: ___min

Stability:
  - Total Checks: ___
  - Successful: ___
  - Failed/Crashes: ___
  - Uptime: ___%
```

---

## 🔧 Troubleshooting Low Scores

### Low Recall (<80%)

1. Check channel coverage
2. Verify monitor mode active
3. Increase scan duration
4. Check for driver issues

```bash
# Verify channels
iw dev wlan0 info | grep channel

# Check if stuck on one channel
iw event -t
```

### High Latency (>1s)

1. Switch to tshark engine
2. Enable buffered storage
3. Check CPU usage
4. Reduce scan frequency

```bash
# Use optimized settings
python sensor_cli.py --engine tshark --buffered-storage
```

### High Packet Loss (>10%)

1. Use dedicated capture tool
2. Reduce processing overhead
3. Increase buffer sizes

```bash
# Increase kernel buffers
sudo sysctl -w net.core.rmem_max=16777216
```

### Stability Issues

1. Enable USB watchdog
2. Check driver stability
3. Increase timeouts

```bash
# Run with watchdog
python sensor_cli.py --watchdog --engine tshark
```

---

## 📅 Recommended Test Schedule

### Before Demo
- [ ] Quick test (5 min)
- [ ] Export poc.json
- [ ] Verify PCAP opens

### Before Defense
- [ ] Standard test (30 min)
- [ ] Generate all artifacts
- [ ] Run recall comparison
- [ ] Document results

### Production Deployment
- [ ] Comprehensive test (2+ hours)
- [ ] Stress test
- [ ] Long-running stability
- [ ] Resource baseline

---

*Use `python tests/benchmark_suite.py --help` for all options*
