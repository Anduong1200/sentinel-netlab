#!/usr/bin/env python3
"""
Sentinel NetLab - Detector Plugin Architecture
Provides extensible interface for adding new detection capabilities.

Usage:
    from sensor.detector_base import BaseDetector, DetectorRegistry
    
    class MyDetector(BaseDetector):
        def ingest(self, data):
            ...
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Type
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# ALERT MODELS
# =============================================================================

class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class DetectorAlert:
    """Standard alert output from detectors"""
    detector_name: str
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_attack: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector_name,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "mitre_attack": self.mitre_attack,
        }


# =============================================================================
# BASE DETECTOR
# =============================================================================

class BaseDetector(ABC):
    """
    Abstract base class for all WIDS detectors.
    
    Implement this interface to add new detection capabilities:
    - Evil Twin Detection
    - Deauth Flood Detection
    - Rogue AP Detection
    - WPS Attack Detection
    - Beacon Anomaly Detection
    - etc.
    """
    
    # Detector metadata (override in subclasses)
    NAME: str = "base_detector"
    DESCRIPTION: str = "Base detector interface"
    VERSION: str = "1.0.0"
    AUTHOR: str = "Sentinel Team"
    
    # MITRE ATT&CK techniques this detector covers
    MITRE_TECHNIQUES: List[str] = []
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize detector with configuration.
        
        Args:
            config: Detector-specific configuration dict
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.alert_count = 0
        self._setup()
    
    def _setup(self):
        """Override for detector-specific initialization"""
        pass
    
    @abstractmethod
    def ingest(self, data: Dict[str, Any]) -> Optional[DetectorAlert]:
        """
        Process incoming data and potentially generate an alert.
        
        Args:
            data: Dictionary containing frame/network data
            
        Returns:
            DetectorAlert if threat detected, None otherwise
        """
        pass
    
    def reset(self):
        """Reset detector state (e.g., for time window reset)"""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Return detector statistics"""
        return {
            "name": self.NAME,
            "enabled": self.enabled,
            "alert_count": self.alert_count,
        }
    
    def create_alert(
        self,
        alert_type: str,
        severity: AlertSeverity,
        title: str,
        description: str,
        **kwargs
    ) -> DetectorAlert:
        """Helper to create standardized alerts"""
        self.alert_count += 1
        return DetectorAlert(
            detector_name=self.NAME,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            mitre_attack=self.MITRE_TECHNIQUES[0] if self.MITRE_TECHNIQUES else None,
            **kwargs
        )


# =============================================================================
# DETECTOR REGISTRY
# =============================================================================

class DetectorRegistry:
    """
    Registry for detector plugins.
    
    Usage:
        registry = DetectorRegistry()
        registry.register(EvilTwinDetector)
        registry.register(DeauthFloodDetector)
        
        # Process data through all detectors
        for alert in registry.process(frame_data):
            handle_alert(alert)
    """
    
    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}
        self._detector_classes: Dict[str, Type[BaseDetector]] = {}
    
    def register(self, detector_class: Type[BaseDetector], config: Dict = None):
        """Register and instantiate a detector"""
        name = detector_class.NAME
        self._detector_classes[name] = detector_class
        self._detectors[name] = detector_class(config or {})
        logger.info(f"Registered detector: {name} v{detector_class.VERSION}")
    
    def unregister(self, name: str):
        """Unregister a detector"""
        if name in self._detectors:
            del self._detectors[name]
            del self._detector_classes[name]
    
    def get(self, name: str) -> Optional[BaseDetector]:
        """Get detector by name"""
        return self._detectors.get(name)
    
    def list_detectors(self) -> List[Dict[str, Any]]:
        """List all registered detectors"""
        return [
            {
                "name": d.NAME,
                "description": d.DESCRIPTION,
                "version": d.VERSION,
                "enabled": d.enabled,
            }
            for d in self._detectors.values()
        ]
    
    def process(self, data: Dict[str, Any]) -> List[DetectorAlert]:
        """
        Run data through all enabled detectors.
        
        Args:
            data: Frame or network data
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for detector in self._detectors.values():
            if not detector.enabled:
                continue
            
            try:
                alert = detector.ingest(data)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Detector {detector.NAME} error: {e}")
        
        return alerts
    
    def get_stats(self) -> Dict[str, Dict]:
        """Get stats from all detectors"""
        return {
            name: detector.get_stats()
            for name, detector in self._detectors.items()
        }


# =============================================================================
# GLOBAL REGISTRY (Convenience)
# =============================================================================

_global_registry = DetectorRegistry()


def get_registry() -> DetectorRegistry:
    """Get the global detector registry"""
    return _global_registry


def register_detector(detector_class: Type[BaseDetector], config: Dict = None):
    """Register a detector to the global registry"""
    _global_registry.register(detector_class, config)


def process_frame(data: Dict[str, Any]) -> List[DetectorAlert]:
    """Process a frame through all registered detectors"""
    return _global_registry.process(data)
