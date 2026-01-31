# Experiment Reproduction Steps

Follow these steps to reproduce the evaluation results presented in the report.

## Step 1: Environment Setup
Supported OS: Ubuntu 22.04 LTS or Raspberry Pi OS (Bullseye).

1. **Clone Repository**:
   ```bash
   git clone https://github.com/anduong1200/sentinel-netlab.git
   cd sentinel-netlab
   ```
2. **Install Dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Step 2: Generate Test Data
Create the synthetic attack vectors.
```bash
python tests/data/generate_pcap.py
# Verify output exists at tests/data/golden_vectors.pcap
```

## Step 3: Run Replay Simulation
Execute the integration test that replays the PCAP through the sensor logic.
```bash
pytest tests/integration/test_scenarios.py
```

## Step 4: Verify Results
Check the output logs for:
- **Evil Twin Alert**: Score > 90, Type "evil_twin".
- **Deauth Alert**: Type "dos", Count > Threshold.

## Step 5: (Optional) Full Docker Deployment
To test the full stack including the Controller:
```bash
docker compose up -d
# Access dashboard at http://localhost:3000
```
