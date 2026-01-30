# System Architecture Overview

Sentinel-NetLab follows a distributed sensor–controller architecture designed
to reflect real-world wireless monitoring deployments.

## Components
- Sensor: Passive wireless monitor operating in monitor mode
- Controller: Central ingestion, detection, scoring, and alerting service
- Dashboard: Visualization and analyst-facing interface
- Lab Attack Service (Mode B): Isolated research-only attack module

## Design Rationale
- Separation of concerns prevents sensor compromise from escalating to control.
- Centralized detection enables cross-sensor correlation.
- Isolation of attack capabilities enforces ethical research boundaries.

## Non-Goals
- Competing with vendor-grade ASIC-based WIPS
- Autonomous attack response without human approval
- Detection of proprietary or encrypted vendor telemetry
