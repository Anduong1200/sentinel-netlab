#!/bin/bash
# ==========================================
# Run Sentinel Sensor Locally (Development)
# ==========================================

export ENVIRONMENT="development"
export SENSOR_ID="local-demo-sensor"
if [ -f "ops/.env.lab" ]; then
    echo "Lấy token từ ops/.env.lab..."
    export SENSOR_AUTH_TOKEN=$(grep '^SENSOR_AUTH_TOKEN=' ops/.env.lab | cut -d '=' -f2 | tr -d '\r')
    export SENSOR_HMAC_SECRET=$(grep '^CONTROLLER_HMAC_SECRET=' ops/.env.lab | cut -d '=' -f2 | tr -d '\r')
else
    export SENSOR_AUTH_TOKEN="test-token-123"  # gitleaks:allow
    export SENSOR_HMAC_SECRET="dev-secret-super-long-12345678"  # gitleaks:allow
fi

export CONTROLLER_URL="http://127.0.0.1:8080/api/v1/telemetry"
export STORAGE_PATH="./data"

echo "🚀 Bật Sensor ở chế độ Local Development..."
python3 sensor/cli.py --sensor-id "$SENSOR_ID" --upload-url "$CONTROLLER_URL" --config-file config.yaml "$@"
