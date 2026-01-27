# Thesis Defense Evaluation Rubric

> Complete evaluation framework for Sentinel NetLab project (100 points total)

---

## 📊 Score Summary

| Category | Weight | Max Points | Score | Notes |
|----------|--------|------------|-------|-------|
| A. Technical & Functional | 30% | 30 | ____ | |
| B. Security & Ethics | 15% | 15 | ____ | |
| C. Features & Scope | 20% | 20 | ____ | |
| D. Performance & Reliability | 15% | 15 | ____ | |
| E. Documentation & Reproducibility | 10% | 10 | ____ | |
| F. Usability / UX | 5% | 5 | ____ | |
| G. Innovation & Research | 5% | 5 | ____ | |
| **TOTAL** | **100%** | **100** | **____** | |

---

## A. Technical & Functional (30 points)

### A1. Sensor - Monitor & Capture (10 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| Monitor mode enables | `iw dev wlan0 info` shows type monitor | iw_dev.txt | 3 |
| Packet capture works | tshark/scapy captures beacons in 10s | sample.pcap | 3 |
| Channel hopping | Sensor switches channels automatically | Logs/status | 2 |
| Stability | No crashes during 5-min capture | stability_report.txt | 2 |

**Score: ____ / 10**

### A2. Parser & Data Correctness (8 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| SSID accuracy | Compare with airodump-ng | recall_report.txt | 2 |
| BSSID accuracy | Compare with ground truth | recall_report.txt | 2 |
| RSSI/Signal | Reasonable dBm values (-90 to -20) | poc.json | 2 |
| Encryption detection | WPA/WPA2/WPA3/WEP correctly identified | Sample output | 2 |

**Threshold**: SSID/BSSID accuracy ≥99% = full, ≥95% = partial

**Score: ____ / 8**

### A3. Controller & API (6 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| /health endpoint | HTTP 200, valid JSON | curl output | 1 |
| /status endpoint | Returns sensor state | curl output | 1 |
| /networks endpoint | Returns network list | curl output | 2 |
| /export/csv | Generates valid CSV | exported.csv | 2 |

**Score: ____ / 6**

### A4. Integration E2E (6 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| Sensor→Controller flow | Start scan from GUI | demo_video.mp4 | 2 |
| Data display | Networks shown in UI | Screenshot | 2 |
| Export function | CSV exported successfully | CSV file | 2 |

**Score: ____ / 6**

---

## B. Security & Ethics (15 points)

### B1. Transport Security (6 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| TLS/HTTPS | API uses HTTPS | Certificate config | 4 |
| SSH tunnel documented | Alternative documented | README | 2 |

**Note**: API_KEY only without TLS = 3 pts max

**Score: ____ / 6**

### B2. Secrets & Privilege (5 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| API key from env/config | Not hardcoded | Code review | 2 |
| Non-root service | systemd user= or capability-based | Service file | 2 |
| Minimal privilege | Helper scripts restricted | Code review | 1 |

**Score: ____ / 5**

### B3. Ethics/Legal Controls (4 pts)

| Criterion | Test Method | Evidence | Points |
|-----------|-------------|----------|--------|
| Consent form template | Exists and complete | docs/legal_ethics.md | 2 |
| Legal warnings | Documented | README/docs | 1 |
| Mock mode default | Exists | Code/config | 1 |

**Score: ____ / 4**

---

## C. Features & Scope (20 points)

### C1. Core Features (MVP) (10 pts)

| Feature | Status | Evidence | Points |
|---------|--------|----------|--------|
| Sensor capture | ✓/✗ | Demo | 2 |
| Channel hopping | ✓/✗ | Logs | 2 |
| Parsing | ✓/✗ | JSON output | 2 |
| GUI controller | ✓/✗ | Screenshot | 2 |
| Export | ✓/✗ | CSV file | 2 |

**Score: ____ / 10**

### C2. Forensics Support (6 pts)

| Feature | Status | Evidence | Points |
|---------|--------|----------|--------|
| PCAP rotation | ✓/✗ | Config/code | 2 |
| Session indexing | ✓/✗ | Database schema | 2 |
| Wireshark compatible | ✓/✗ | Open PCAP | 2 |

**Score: ____ / 6**

### C3. Extensibility (4 pts)

| Criterion | Status | Evidence | Points |
|-----------|--------|----------|--------|
| Modular code | ✓/✗ | Architecture | 2 |
| Multi-sensor ready | ✓/✗ | API design | 1 |
| Roadmap documented | ✓/✗ | README | 1 |

**Score: ____ / 4**

---

## D. Performance & Reliability (15 points)

### D1. Recall (Detection Rate) (6 pts)

| Recall | Points |
|--------|--------|
| ≥ 80% | 6 (full) |
| 60-79% | 4 (partial) |
| < 60% | 0-2 (fail) |

**Test**: `python tests/compare_recall.py gt.csv poc.json`

**Measured Recall**: _____%  
**Score: ____ / 6**

### D2. Latency / Responsiveness (4 pts)

| Metric | Target | Points |
|--------|--------|--------|
| Average RTT | < 1s | 4 (full) |
| Average RTT | 1-2s | 2 (partial) |
| P95 RTT | < 2s | Required |

**Test**: `python tests/test_latency.py -n 50`

**Measured Avg**: ____ms  
**Measured P95**: ____ms  
**Score: ____ / 4**

### D3. Stability (5 pts)

| Crashes | Points |
|---------|--------|
| 0 | 5 (full) |
| 1 | 3 (partial) |
| ≥ 2 | 0-2 (fail) |

**Test**: `python tests/test_stability.py -d 30 -i 2`

**Measured Crashes**: ____  
**Score: ____ / 5**

---

## E. Documentation & Reproducibility (10 points)

### E1. Setup Guide & Runbook (6 pts)

| Item | Status | Points |
|------|--------|--------|
| setup_vm.sh or equivalent | ✓/✗ | 2 |
| check_driver.py | ✓/✗ | 2 |
| demo_runbook.md | ✓/✗ | 2 |

**Reproducibility Test**: Can reviewer rebuild in 2 hours?

**Score: ____ / 6**

### E2. Tests & Artifacts (4 pts)

| Item | Status | Points |
|------|--------|--------|
| Test scripts | ✓/✗ | 1 |
| compare_recall.py | ✓/✗ | 1 |
| Sample PCAP | ✓/✗ | 1 |
| poc.json | ✓/✗ | 1 |

**Score: ____ / 4**

---

## F. Usability / UX (5 points)

### User Testing (5 pts)

| Criterion | Method | Result |
|-----------|--------|--------|
| Task completion | 3 non-expert users attempt basic scan | ___/3 completed |
| Error messages | Helpful and actionable | ✓/✗ |
| Visual clarity | UI organized and readable | ✓/✗ |

**Threshold**: ≥2/3 complete basic task = full points

**Score: ____ / 5**

---

## G. Innovation & Research (5 points)

| Criterion | Evidence | Points |
|-----------|----------|--------|
| Novel detection heuristics | Code/paper | 2 |
| Dataset contribution | Public/private dataset | 1 |
| Empirical evaluation | Benchmark results | 1 |
| Future research discussion | Report section | 1 |

**Note**: Basic PoC = 2-3 pts, Significant contribution = 5 pts

**Score: ____ / 5**

---

## 📝 Final Score Calculation

| Category | Weight | Score | Weighted |
|----------|--------|-------|----------|
| A. Technical | 30% | __/30 | ____ |
| B. Security | 15% | __/15 | ____ |
| C. Features | 20% | __/20 | ____ |
| D. Performance | 15% | __/15 | ____ |
| E. Docs | 10% | __/10 | ____ |
| F. UX | 5% | __/5 | ____ |
| G. Innovation | 5% | __/5 | ____ |
| **TOTAL** | | | **____/100** |

---

## 📊 Grade Conversion

| Score | Grade | Description |
|-------|-------|-------------|
| 90-100 | A / Excellent | Outstanding work |
| 80-89 | B / Good | Above average |
| 70-79 | C / Satisfactory | Meets requirements |
| 60-69 | D / Pass | Minimum acceptable |
| < 60 | F / Fail | Does not meet requirements |

---

## 🚨 Critical Criteria

The following MUST pass for overall acceptance:

1. [ ] Monitor mode works (A1)
2. [ ] Parser accuracy ≥ 95% (A2)
3. [ ] Consent form exists (B3)
4. [ ] Core features work (C1)

If any critical criterion fails, include explanation in "Limitations" section.

---

## 📋 Evaluator Notes

```
Strengths:


Areas for Improvement:


Overall Comments:


Evaluator: ________________________  Date: ____________
```

---

*Based on standard thesis evaluation criteria for security tools*
