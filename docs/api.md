# API Documentation

The Sentinel NetLab API follows the OpenAPI 3.0 specification.

## Interactive Documentation
- **Swagger UI**: Visit `/api/docs` (if enabled in development) or load `openapi.yaml` into [Swagger Editor](https://editor.swagger.io/).
- **Spec File**: `controller/openapi.yaml`

## Detailed References
- [Controller Ingestion API](reference/api_ingest.md): For Sensor -> Controller telemetry and alerts.
- [Sensor Local API](reference/api_overview.md): For local agent status and standalone tools.

## Core Endpoints
### Telemetry
- `POST /api/v1/telemetry`: Ingest sensor data.
- `GET /api/v1/telemetry`: Retrieve recent records.

### Alerts
- `POST /api/v1/alerts`: Create security alerts.
- `GET /api/v1/alerts`: List active threats.

### Management
- `POST /api/v1/sensors/heartbeat`: Sensor keep-alive.
- `GET /api/v1/health`: System status check.
