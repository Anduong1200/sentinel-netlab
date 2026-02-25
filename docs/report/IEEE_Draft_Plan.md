# IEEE Report Draft Plan: Sentinel NetLab

Based on the project's source code and current documentation (`IEEE_Sentinel_NetLab_Report.md`), here is a structured plan to finalize the IEEE report. This plan maps sections of the report to the actual components of the codebase.

## 1. Abstract
*   **Objective:** Summarize the core contribution—Sentinel NetLab as a lightweight, scalable, hybrid WIDS.
*   **Key Results:** Highlight precision (~94.2% Evil Twin, ~97.8% Deauth Flood) and MTTD (< 2.5s).

## 2. Introduction
*   **Context:** Highlight the vulnerability of 802.11 management frames (unencrypted nature).
*   **Problem Statement:** Educational institutions lack accessible, open-source, and transparent WIDS platforms.
*   **Contributions:** Distributed sensor network, novel risk scoring algorithm, ethical/authorized design.

## 3. Related Work
*   *Compare with existing tools:* Kismet (passive, no risk scoring), Aircrack-ng (offensive-focused), Commercial WIPS (Cisco/Aruba - costly).

## 4. Threat Model
*   **Reference Code:** `docs/architecture/threat_model.md`
*   **Categories to cover:** Impersonation (Evil Twin, Rogue AP), DoS (Deauth Floods).

## 5. System Architecture
*   **Sensor Layer (`sensor/`)**
    *   *Capture Driver* (`capture_driver.py` / `capture_tshark.py`)
    *   *Frame Parsing & Normalization* (`frame_parser.py`, `normalizer.py`)
*   **Controller Layer (`controller/`)**
    *   *API & Aggregation* (`api_server.py`)
    *   *Data Storage* (PostgreSQL/TimescaleDB integrations via `db/`)
*   **Dashboard (`dashboard/`)**
    *   *Visualization* (Plotly/Dash based real-time mapping)

## 6. Detection Algorithms
*   **Evil Twin Detection (`algos/evil_twin.py`)**
    *   Detail the multi-factor scoring algorithm (SSID matching, BSSID verification, RSSI profiling, security capability matching).
*   **Deauth/DoS Detectors (`algos/dos.py`, `algos/disassoc_detector.py`)**
    *   Detail the sliding window threshold approach (e.g., 10 frames/sec anomaly trigger).
*   **Risk Scoring Engine (`algos/risk.py`)**
    *   Explain the formula for composite risk (weighing encryption, RSSI, vendor trust).

## 7. Implementation & Methodology
*   **Timeline:** Detail the 8-week structured development cycle.
*   **Test Environment:** Setup details (3x Raspberry Pi 4s, Alfa AWUS036ACH adapters).
    *   *Controller:* Ubuntu 22.04 LTS VM (4 vCPU, 8GB RAM).
*   **Attack Simulation (`examples/`, `lab_attack_service/`):** How Evil Twin and Deauth attacks were safely simulated in the lab.
*   **Anonymization:** Feature details on MAC hashing: `H(mac) = SHA256(mac || salt)` for PII compliance.
*   **Telemetry Schema:** Document structure (BSSID, RSSI, Flags).

## 8. Experimental Evaluation
*   **Reference Code:** `benchmarks/benchmark_suite.py`, `benchmarks/compare_recall.py`
*   **Metrics to Present:** Precision, Recall, F1-Score, and MTTD (Mean Time To Detect).
*   **Latency:** Note that 95% of threats are detected within 1.2s.
*   **Resource Analysis:** CPU/RAM consumption mapping (Sensor vs. Controller VMs). Sensor load peaked at 42% under intense flood attacks but remained <15% normally. 

## 9. Conclusion & Future Work
*   **Limitations:** 5GHz coverage, WPA3 encrypted management frames limitations.
*   **Future Scope:** Transitioning from rule-based to ML-driven anomaly detection (referencing `ml/anomaly_model.py`).

---
*Note: This plan serves as the structural foundation for finalizing the `IEEE_Sentinel_NetLab_Report.md`. Each section should be fleshed out with direct code examples and metrics derived from the `benchmarks/` suite.*
