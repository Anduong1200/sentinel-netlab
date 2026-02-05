
# Sentinel NetLab Tuning Guide

## Baseline Profiling
The specific logic for determining if a network is "normal" relies on the `BaselineProfile`.

### Warm-up Period
Detectors will NOT penalize anomalies heavily if a profile is still in "Warm-up" mode.
- **Duration**: 3 Days default.
- **Samples**: 100 Samples minimum.

### Thresholds
- **RSSI**: Detectors flag an anomaly if signal is > `baseline_max + 15dBm`.
- **Channel**: Strict matching against previously seen channel list.

## Risk Scoring
Risk is calculated as: `Risk = Confidence * Impact`.

### Confidence (0.0 - 1.0)
- **1.0**: Certainty (e.g., Static Policy Violation).
- **0.5 - 0.9**: Heuristic (e.g., Baseline Deviation).
- **< 0.5**: Weak Signal (e.g., Single packet anomaly).

### Impact (0 - 100)
- **High (90-100)**: Active Threat (Rogue AP, Deauth).
- **Medium (40-60)**: Configuration Risk (Open Network).
- **Low (10-30)**: Noise / Info.

### Severity Mapping
- **CRITICAL**: Risk >= 90
- **HIGH**: Risk >= 70
- **MEDIUM**: Risk >= 40
- **LOW**: Risk < 40

## Smart Triage (Deduplication)
Events are deduplicated to prevent alert fatigue.

- **Fingerprint**: `DetectorID + Entity + Reason`.
- **Suppression Window**: 1 Hour (Default).
- **Escalation**: If a higher severity event occurs for the exact same fingerprint (e.g., risk score increases), it **bypasses** the suppression window immediately.
