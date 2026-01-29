# ⚠️ Availability Report: Operational Risks

## 1. Single Point of Failure (Controller)
- **Risk**: The architecture relies on a single `Controller` instance (`controller/api_server.py`). If this goes down, Sensors cache locally but cannot upload or receive commands.
- **Failover**: No automated failover or load balancing mechanism is documented or implemented.
- **Mitigation**: Deploy behind a Load Balancer (Nginx/HAProxy) and use an external DB (Postgres) instead of SQLite to allow multiple Controller instances.

## 2. Sensor Resilience
- **Risk**: `sensor/sensor_controller.py` runs as a single process. If the `CaptureDriver` crashes (e.g., driver instability), the entire sensor stops.
- **Recoverability**: Systemd service (`ops/systemd/sentinel-sensor.service`) handles restart, but internal crash handling could be improved (e.g., separate process for capture vs upload).
- **Buffer**: `BufferManager` uses disk journaling, which is good, but SD card corruption on Raspberry Pi is a known risk with high-write journalling.

## 3. Deployment Complexity
- **Risk**: Manual installation (`quickstart.md`) is error-prone (dependencies, monitor mode drivers).
- **Automation**: Docker containers exist but "host networking" requirements for Monitor Mode make Docker deployment tricky on non-Linux platforms or specific kernel versions.
- **Mitigation**: Create a pre-built standard `.img` for Raspberry Pi (Packer + Ansible).

## 4. Scalability
- **Risk**: `SQLite` default in `controller` will bottleneck quickly with >10 sensors sending 200/records batch every 5 seconds.
- **Mitigation**: Enforce PostgreSQL for any "Production" deployment.

## 5. Security of Operations
- **Risk**: API Token is hardcoded (`sentinel-dev-2024`) or passed via minimal Env Vars. No mutual TLS (mTLS) for Sensor-Controller communication.
- **Mitigation**: Implement mTLS certificates (generated via `ops/scripts/generate-certs.sh`) and enforce their use.

## Failure Modes Analysis
| Component | Failure Mode | Detectability | Recovery |
|-----------|--------------|---------------|----------|
| Sensor | Driver Crash | High (Heartbeat miss) | Systemd Restart |
| Sensor | Disk Full (Journal) | Low (Silent drop) | Manual Cleanup |
| Controller| OOM / Crash | High (HTTP 500) | Docker/Service Restart |
| Database | Corruption | Medium (Logs) | Restore from Backup |
