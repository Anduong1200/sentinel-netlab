"""
Sentinel NetLab - Sensor-Side Detector Contract

Defines BaseSensorDetector, intentionally compatible with
controller/detection/interface.py AbstractDetector.process() shape.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseSensorDetector(ABC):
    """
    Base contract for all sensor-side detector adapters.

    Each adapter wraps an existing algo detector and exposes
    a unified ``process()`` interface returning normalized alert dicts.

    Subclasses may set the following **class-level** metadata to enable
    cheap prefilter routing in the orchestrator:

    * ``supported_event_types`` — frame_type values this detector cares about.
    * ``supported_frame_subtypes`` — integer frame subtypes of interest.
    * ``required_fields`` — telemetry keys that must be present.

    When any of these is ``None`` (default) the detector is called for
    *every* telemetry item (conservative / backward-compatible).
    """

    detector_id: str = ""

    # ── Routing metadata (optional, cheap prefilter) ────────────────────
    supported_event_types: set[str] | None = None
    supported_frame_subtypes: set[int] | None = None
    required_fields: set[str] | None = None

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def process(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Analyze a single telemetry record.

        Args:
            telemetry: Parsed frame / network dict from the sensor pipeline.
            context: Optional context (e.g. sensor_id).

        Returns:
            List of normalized alert dicts (may be empty).
        """

    # ── Convenience ─────────────────────────────────────────────────────

    def accepts(self, telemetry: dict[str, Any]) -> bool:
        """
        Cheap pre-check: return *False* only when *telemetry* is clearly
        irrelevant for this detector.  The orchestrator calls this before
        ``process()`` to short-circuit obvious mismatches.

        Default implementation checks ``supported_event_types``,
        ``supported_frame_subtypes``, and ``required_fields``.
        """
        if self.supported_event_types is not None:
            frame_type = telemetry.get("frame_type")
            if frame_type and frame_type not in self.supported_event_types:
                return False

        if self.supported_frame_subtypes is not None:
            subtype = telemetry.get("frame_subtype")
            if subtype is not None and subtype not in self.supported_frame_subtypes:
                return False

        if self.required_fields is not None:
            if not self.required_fields.issubset(telemetry.keys()):
                return False

        return True
