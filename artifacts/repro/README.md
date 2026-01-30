# Replication Package

This bundle contains the necessary scripts to automate the reproduction of the experimental results presented in the Sentinel NetLab report.

## Contents
- `reproduce_all.ps1`: Windows PowerShell automation script.
- `reproduce_all.sh`: (Planned) Linux automation script.

## Usage

### Windows
```powershell
.\artifacts\repro\reproduce_all.ps1
```

### Linux
Please follow the manual steps in [Experiment Steps](../../docs/reproducibility/experiment_steps.md).

## output
The script will:
1. Verify Python environment.
2. Generate synthetic attack vectors in `tests/data/golden_vectors.pcap`.
3. Run the `test_scenarios.py` integration suite to parse the PCAP and verify the `Evil Twin` and `DoS` detection alerts trigger as expected.
