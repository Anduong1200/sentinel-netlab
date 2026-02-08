from typing import Any

from common.detection.evidence import Finding
from controller.detection.interface import AbstractDetector


class DetectionPipeline:
    """
    Test Harness to run multiple detectors against a stream of telemetry.
    """

    def __init__(self):
        self.detectors: list[AbstractDetector] = []

    def register(self, detector: AbstractDetector):
        self.detectors.append(detector)

    def run(
        self,
        telemetry_stream: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Run all detectors against the stream.
        aggregated_findings: Flat list of all findings.
        """
        all_findings = []
        context = context or {}

        for item in telemetry_stream:
            for detector in self.detectors:
                findings = detector.process(item, context)
                all_findings.extend(findings)

        return all_findings
