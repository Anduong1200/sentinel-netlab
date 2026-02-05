
from typing import List, Dict, Any
from controller.detection.interface import AbstractDetector
from common.detection.evidence import Finding

class DetectionPipeline:
    """
    Test Harness to run multiple detectors against a stream of telemetry.
    """
    
    def __init__(self):
        self.detectors: List[AbstractDetector] = []

    def register(self, detector: AbstractDetector):
        self.detectors.append(detector)

    def run(self, telemetry_stream: List[Dict[str, Any]], context: Dict[str, Any] = None) -> List[Finding]:
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
