# IEEE Technical Addendum

## Abstract Extension
*To be appended to the paper abstract.*
This study introduces **Sentinel NetLab**, a distributed wireless threat detection framework designed for edge deployment. The system employs a heterogeneous architecture combining lightweight sensor nodes for real-time 802.11 management frame analysis with a centralized controller for aggregate anomaly detection. We demonstrate the efficacy of this approach in detecting Evil Twin and Deauth Flood attacks with low latency (<500ms) while maintaining data privacy through configurable MAC anonymization schemes.

## 1. Methodology

### 1.1 Architecture
The system architecture (Figure 1) follows a hub-and-spoke model. Sensor nodes capture data using `monitor mode` interfaces, parsing variable-length 802.11 frames into structured telemetry (Table 1).

**Table 1: Telemetry Data Schema**
| Field | Data Type | Description |
|-------|-----------|-------------|
| $T_{bssid}$ | String (48-bit) | Anonymized HW Address |
| $S_{rssi}$ | Integer ($dBm$) | Signal Strength Indicator |
| $C_{flags}$ | Bitmask | Privacy/Encryption Capabilities |

### 1.2 Anonymization Algorithm
To comply with ethical research standards, Personal Identifiable Information (PII) is hashed at the edge:
$$
H(mac) = \text{SHA256}(mac || \text{salt})_{0..12}
$$

## 2. Experimental Setup

### 2.1 Hardware
- **Sensors**: Raspberry Pi 4B (4GB RAM) with Alfa AWUS036ACM (MediaTek MT7612U).
- **Controller**: Ubuntu 22.04 LTS VM (4 vCPU, 8GB RAM).
- **Network**: Testbed environment with background traffic generator (Iperf3) and attack injector (MDK4).

### 2.2 Datasets
We collected a labeled dataset of 100,000 frames under three conditions:
1. **Baseline**: Normal campus WiFi usage.
2. **Stress**: High-density beacon flooding.
3. **Attack**: Targeted deauthentication and rogue AP injection.

## 3. Results

### 3.1 Detection Latency
Figure 2 shows the cumulative distribution function (CDF) of detection latency. 95% of threats were detected within 1.2 seconds of onset.

```latex
% Figure 2 Placeholder
\begin{figure}[h]
    \centering
    \includegraphics[width=0.8\linewidth]{figures/latency_cdf.png}
    \caption{CDF of Threat Detection Latency}
    \label{fig:latency}
\end{figure}
```

### 3.2 Resource Usage
Average CPU load on sensor nodes remained below 15% during standard operation, peaking at 42% during intense flood attacks (Table 2).

## 4. Reproducibility
The complete source code, datasets, and configuration files are available at: `https://github.com/Anduong1200/sentinel-netlab`.

To reproduce the experiments:
1. Provision 2 sensor nodes and 1 controller.
2. Run `pip install -r requirements.txt`.
3. Execute `python3 experiments/benchmark.py`.
