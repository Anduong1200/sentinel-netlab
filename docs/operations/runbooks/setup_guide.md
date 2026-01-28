# Sensor Setup Runbook

## Objective
Deploy and configure a new Sentinel Sensor node.

## Prerequisites
- Hardware: Raspberry Pi or Linux Machine with WiFi adapter supporting Monitor Mode.
- OS: Raspbian 11+ or Ubuntu 22.04.
- Network: Outbound HTTPS access to Controller.

## Steps

### 1. Environment Preparation
Install system dependencies:
```bash
sudo apt update
sudo apt install -y python3-venv libpcap-dev wireless-tools
```

### 2. Clone & Install
```bash
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configuration
Copy the example config:
```bash
cp config.example.yaml config.yaml
```
Edit `config.yaml` to set your Controller URL and API Key:
```yaml
api:
  host: "controller.example.com"
  api_key: "YOUR_PROVISIONED_KEY"
```

### 4. Service Installation
Install systemd service (if running as daemon):
```bash
sudo cp packaging/sentinel-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-sensor
```

### 5. Verification
Check logs to confirm initialization:
```bash
journalctl -u sentinel-sensor -f
```
Look for: `INFO: Sensor initialized successfully`

## Troubleshooting

- **Error**: `Operation not supported`
  - **Cause**: WiFi card does not support Monitor Mode.
  - **Fix**: Verify hardware or update drivers.

- **Error**: `Connection refused`
  - **Cause**: Controller offline or firewall blocking port 5000.
