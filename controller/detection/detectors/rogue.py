
from typing import List, Dict, Any, Optional
from controller.detection.interface import AbstractDetector
from controller.baseline.store import BaselineStore
from common.detection.evidence import Finding, Evidence
from common.detection.reason_codes import ReasonCodes

class RogueAPDetector(AbstractDetector):
    """
    Detects rogue APs by comparing against site baselines.
    Checks: Channel Stability, RSSI Range.
    """
    
    def __init__(self, baseline_store: BaselineStore, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.store = baseline_store

    def process(self, telemetry: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        findings = []
        site_id = context.get("site_id") if context else None
        
        if not site_id:
            return [] # Cannot baseline without site context

        ssid = telemetry.get("ssid")
        if not ssid:
            return []
            
        security = telemetry.get("security", "")
        bssid = telemetry.get("bssid", "")
        channel = str(telemetry.get("channel", ""))
        rssi = telemetry.get("rssi_dbm")
        
        network_key = f"{ssid}|{security}"
        profile = self.store.get_profile(site_id, network_key)
        
        if not profile:
            # New/Unknown Network observed in this site
            # If explicit "authorized_ssids" list exists, we could flag known-SSID-but-no-profile here
            # For now, we only detect anomalies on KNOWN profiles (deviations)
            return []

        # 1. Channel Mismatch
        # If channel never seen in baseline -> Anomaly
        known_channels = profile.features.get("channels", {})
        if channel and channel not in known_channels:
            f = Finding(
                detector_id="rogue_channel_dev",
                entity_key=f"rogue|{ssid}|{bssid}",
                confidence_raw=0.8
            )
            f.add_reason(ReasonCodes.CHANNEL_MISMATCH)
            f.evidence_list.append(Evidence(
                type="signal_anomaly",
                description=ReasonCodes.CHANNEL_MISMATCH.format(
                    bssid=bssid, channel=channel, baseline_channels=str(list(known_channels.keys()))
                ),
                data={"channel": channel, "baseline": known_channels}
            ))
            findings.append(f)

        # 2. RSSI Anomaly
        # If RSSI significantly stronger than baseline max -> Potential Evil Twin (close proximity)
        rssi_stats = profile.features.get("rssi", {})
        if rssi is not None and rssi_stats.get("max"):
            baseline_max = rssi_stats["max"]
            # Threshold: 15dBm stronger than ever seen
            if rssi > (baseline_max + 15):
                 f = Finding(
                    detector_id="rogue_rssi_spike",
                    entity_key=f"rogue|{ssid}|{bssid}",
                    confidence_raw=0.6
                )
                 f.add_reason(ReasonCodes.RSSI_ANOMALY)
                 f.evidence_list.append(Evidence(
                    type="signal_anomaly",
                    description=ReasonCodes.RSSI_ANOMALY.format(
                        rssi=rssi, expected_range=f"Max {baseline_max}"
                    ),
                    data={"rssi": rssi, "baseline_max": baseline_max}
                ))
                 findings.append(f)

        return findings
