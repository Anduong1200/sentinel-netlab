"""
Sentinel NetLab - Sensor Analysis Orchestrator

Encapsulates the sensor's post-detection analysis pipeline:
  1. Baseline deviation checking
  2. Risk scoring
  3. Exploit chain correlation

This keeps sensor_controller.py thin and provides a single
integration point for all analysis logic.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SensorAnalysisOrchestrator:
    """
    Coordinates risk/baseline/chain analysis on telemetry and alerts.

    Typical usage from SensorController::

        analysis = SensorAnalysisOrchestrator(
            risk_engine=risk_engine,
            baseline=baseline,
            chain_analyzer=chain_analyzer,
            sensor_id=sensor_id,
        )

        # Per-frame analysis (risk + baseline)
        extra_alerts = analysis.analyze_telemetry(telemetry_dict, frame_count)

        # Per-alert chain correlation
        chain_alert = analysis.correlate_alert(alert_dict)
    """

    def __init__(
        self,
        risk_engine: Any,
        baseline: Any,
        chain_analyzer: Any,
        sensor_id: str = "",
        metrics: Any = None,
    ):
        self.risk_engine = risk_engine
        self.baseline = baseline
        self.chain_analyzer = chain_analyzer
        self.sensor_id = sensor_id
        self.metrics = metrics

    # ── Per-frame analysis ───────────────────────────────────────────────

    def analyze_telemetry(
        self,
        telemetry_dict: dict[str, Any],
        bssid: str = "",
        ssid: str = "",
        frame_count: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Run baseline deviation and risk scoring on a telemetry item.

        Only executes on every 10th frame (same cadence as the original)
        and only when baseline is not in learning mode.

        Returns:
            A list of alert dicts (0 or 1).
        """
        if frame_count % 10 != 0:
            return []

        deviation = self.baseline.check_deviation(telemetry_dict)

        if self.baseline.learning_mode:
            return []

        dev_score = deviation["score"] if deviation else 0.0
        risk_result = self.risk_engine.calculate_risk(
            telemetry_dict, deviation_score=dev_score
        )
        current_score = risk_result.get("risk_score", 0)

        alerts: list[dict[str, Any]] = []

        if deviation:
            logger.warning(
                "Baseline Deviation [%s]: %s (%s)",
                deviation["score"],
                deviation["reasons"],
                ssid,
            )
            alerts.append(
                {
                    "alert_type": "baseline_deviation",
                    "severity": "high" if current_score > 70 else "medium",
                    "title": f"Baseline Deviation: {ssid}",
                    "description": "; ".join(deviation["reasons"]),
                    "evidence": deviation.get("baseline"),
                    "risk_score": current_score,
                    "bssid": bssid,
                    "ssid": ssid,
                    "impact": risk_result.get("impact", 0.5),
                    "confidence": risk_result.get("confidence", 0.5),
                    "sensor_id": self.sensor_id,
                }
            )
        elif current_score > 70:
            logger.warning("High Risky Network: %s (Score: %s)", ssid, current_score)

        # Update metrics if available.
        if self.metrics and bssid:
            self.metrics.set_risk_score(bssid, current_score)

        return alerts

    # ── Per-alert correlation ────────────────────────────────────────────

    def correlate_alert(
        self,
        alert_dict: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Run exploit chain analysis on a single alert.

        Returns a chain alert dict if a chain is detected, otherwise None.
        """
        chain_alert = self.chain_analyzer.analyze(alert_dict)
        if chain_alert:
            chain_alert["sensor_id"] = self.sensor_id
            logger.critical("CHAIN DETECTED: %s", chain_alert["title"])
        return chain_alert  # type: ignore
