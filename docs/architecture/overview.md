# System Architecture Overview

Sentinel-NetLab follows a distributed sensor–controller architecture designed
to reflect real-world wireless monitoring deployments.

## Components
- **Sensor Agent**: Lightweight capture and detection agent. Entry point: `sensor/sensor_cli.py`.
- **Controller**: Central ingestion and management service. Production: `ops/docker-compose.prod.yml`.
- **Dashboard**: Real-time visualization platform (Port 8050).
- **Lab Mode (Option B)**: Isolated research-only attack module for authorized environments.

## Design Rationale
- Separation of concerns prevents sensor compromise from escalating to control.
- Centralized detection enables cross-sensor correlation.
- Isolation of attack capabilities enforces ethical research boundaries.

## Non-Goals
- Competing with vendor-grade ASIC-based WIPS
- Autonomous attack response without human approval
- Detection of proprietary or encrypted vendor telemetry
