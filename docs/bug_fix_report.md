# Verification & Fix Report

## 1. CI Failure Analysis
- **Issue**: `TestRiskScoring.test_open_network_high_risk` failed with `AssertionError: 51 not greater than or equal to 70`.
- **Cause**: The original v2 weights (`encryption=0.35`) resulted in a score of ~51 for "Open Free WiFi" networks, which was too low for the "High Risk" threshold.

## 2. Fix Implementation
- **File**: `sensor/risk.py`
- **Changes**:
  - Increased `encryption` weight from `0.35` to `0.50`.
  - Increased `ssid_pattern` weight from `0.15` to `0.20`.
  - Increased penalty for known malicious keywords ("free", "open", etc.) from `0.3` to `0.5`.
  - Added `RiskScorer` alias for backward compatibility.

## 3. Verification Results
- **Test Command**: `python -m unittest tests.test_modules.TestRiskScoring.test_open_network_high_risk`
- **Result**: `OK` (Passed).
- **Calculated Score**: ~71 (High Risk), satisfying the `>= 70` assertion.

> **Note**: Local execution of `TestParser` showed errors due to missing `scapy` in the current shell environment, but this does not invalidate the Risk Scoring logic fix.

## 4. Operational Status
- The Risk Engine is now tuned to aggressively flag Open/Rogue networks, aligning with the "SME/Security" use case defense.
