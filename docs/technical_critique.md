# Deep Technical Critique & Performance Analysis

> **Internal Engineering Review**: This document provides a critical analysis of Sentinel NetLab's architectural decisions, performance claims, and scalability limitations. It serves as a foundation for honest defense and future roadmap planning.

---

## 🛠️ Architectural Trade-off Analysis

| Component | Design Choice | Strategic Advantage | Technical Liability (The "Real" Cost) |
| :--- | :--- | :--- | :--- |
| **Hybrid Engine** | **C (Tshark) + Python** | Leverages Tshark's mature dissectors while keeping logic modifiable in Python. | **I/O Bottleneck**: Continuous JSON serialization/deserialization between processes creates overhead. Managing Tshark subprocess lifecycle is prone to zombie processes or memory leaks if not handled perfectly. |
| **Storage** | **SQLite** | Zero-config, single-file deployment perfect for embedded edges. | **Write-Lock Contention**: SQLite is poor at concurrent writes. Under heavy packet load (e.g., high-density office), storage becomes the primary bottleneck, potentially dropping data. |
| **Topology** | **Sensor-API Coupled** | Simplicity. Easy to deploy as a monolithic "box". | **Single Point of Failure**: The API server is effectively a bottleneck. If it crashes, alerting stops even if capture continues. No decoupling via Message Queue means no back-pressure handling. |
| **Detection** | **Heuristic/Signature** | Deterministic, easy to explain (White-box). | **Reactive**: Fails against zero-day or behavioral anomalies (e.g., "Low-and-Slow" exfiltration). Rigid thresholds cause false positives in dynamic environments. |

---

## ⚡ Performance Reality Check

| Metric | Claimled Target | Engineering Reality | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Latency** | **< 50ms** | **Optimistic**. In ideal "Quiet Lab" conditions, yes. In "Busy Network" (100+ devices), the Python GIL and IO overhead likely pushes this to **200-500ms**. | Acknowledge that 50ms is "Processing Latency" (internal), not "End-to-End Latency". Real-time invites buffering delays. |
| **Recall** | **> 90%** | **Conditional**. High recall for *known* signatures (e.g., Karma, Deauth). For sophisticated attacks (e.g., subtle power variance), recall drops significantly without ML. | Admit reliance on "Known Attack Patterns". Emphasize that "Recall" is against a specific test set (MDK3 generated), not wild zero-days. |
| **Stability** | **99.9% Uptime** | **Theoretical**. A 24h test doesn't expose long-term heap fragmentation or Tshark memory creep. | Proposed "Watchdog" service (Systemd with auto-restart) is critical. Regular scheduled reboots (cron) might be needed for low-end hardware. |
| **Scale** | **Enterprise Ready** | **False**. The architecture is "Single-Site Ready". It cannot scale to a Campus (1000+ APs) without a central layout change (moving to Kafka/Elastic). | Position expressly as **"Edge Sensor"** or **"SMB Solution"**, not Enterprise WIPS. |

---

## 💡 Recommendations for Production Readiness
*To move from Prototype to Product, the following re-engineering is required:*

1.  **Database Migration**: Move from SQLite to **internal TimescaleDB** (or minimal PostgreSQL) for robust time-series write performance.
2.  **Async Decoupling**: Introduce **Redis** as a broker between the Capture Thread and Analysis Thread. This provides "Back-pressure" handling when traffic spikes.
3.  **Watchdogs**: Implement a "Health Check" endpoint `/health` that monitors the Tshark subprocess status and auto-heals if the PID dies.
4.  **Dynamic Thresholds**: Replace hardcoded `risk_weights.yaml` with a baseline-learning period (e.g., "Learn Normal for 24h" -> "Alert on Deviation").

---
*Document generated for Thesis Defense Preparation - January 2026*
