"""
Sentinel NetLab - Sensor-Side Detection Orchestration

Provides a unified detection orchestrator that replaces manual
per-detector wiring in SensorController.
"""

from sensor.detection.orchestrator import SensorDetectionOrchestrator

__all__ = ["SensorDetectionOrchestrator"]
