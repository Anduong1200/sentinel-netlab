#!/bin/bash
# ==========================================
# Run Sentinel Sensor Locally (Development)
# ==========================================

export ENVIRONMENT="development"
export SENSOR_ID="local-demo-sensor"
export SENSOR_AUTH_TOKEN="test-token-123"
export SENSOR_HMAC_SECRET="dev-secret-super-long-12345678"
export CONTROLLER_URL="http://127.0.0.1:8080/api/v1/telemetry"
export STORAGE_PATH="./data"

echo "🚀 Bật Sensor ở chế độ Local Development..."
python3 sensor/cli.py --sensor-id "$SENSOR_ID" --config-file config.yaml "$@"
