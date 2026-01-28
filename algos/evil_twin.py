#!/usr/bin/env python3
"""
Sentinel NetLab - Advanced Evil Twin Detector
Implements scoring-based detection with configurable weights.

Features:
- Near real-time detection with evidence
- Weighted scoring model (0-100)
- Low false positive design
- Resource-constrained friendly
"""

import logging
import statistics
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION (Tunable Parameters)
# =============================================================================

@dataclass
class EvilTwinConfig:
    """Configuration for Evil Twin detection"""
    # Thresholds
    rssi_delta_threshold: int = 15  # dB difference to flag
    jitter_threshold_ms: float = 10.0  # Beacon interval jitter
    new_ap_window_minutes: int = 10  # AP recent appearance window
    min_duplicate_count: int = 2  # Min BSSIDs for same SSID
    sliding_window_seconds: int = 120  # Observation window
    confirmation_window_seconds: int = 30  # Persistence check

    # Score weights (must sum to 100)
    weight_duplicate_ssid: int = 20
    weight_rssi_delta: int = 30
    weight_vendor_mismatch: int = 15
    weight_security_mismatch: int = 15
    weight_beacon_jitter: int = 10
    weight_new_appearance: int = 5
    weight_client_probe: int = 5  # Optional bonus

    # Alert thresholds
    threshold_critical: int = 80
    threshold_high: int = 60
    threshold_medium: int = 40

    # MITRE mapping
    mitre_technique: str = "T1557.002"
    mitre_tactic: str = "Credential Access"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class APProfile:
    """Profile for a tracked Access Point"""
    bssid: str
    ssid: Optional[str]
    channel: int
    vendor_oui: str
    security_type: str  # OPEN, WEP, WPA2, WPA3
    rsn_capabilities: dict = field(default_factory=dict)
    wpa_info: dict = field(default_factory=dict)
    pmf_required: bool = False
    wps_enabled: bool = False

    # Observations
    first_seen: float = 0.0
    last_seen: float = 0.0
    observation_count: int = 0
    sensor_ids: set[str] = field(default_factory=set)

    # Metrics
    rssi_samples: list[int] = field(default_factory=list)
    beacon_intervals: list[int] = field(default_factory=list)
    channels_seen: set[int] = field(default_factory=set)

    # IEs present
    ies_present: list[str] = field(default_factory=list)
    vendor_ies: list[str] = field(default_factory=list)

    @property
    def avg_rssi(self) -> float:
        return statistics.mean(self.rssi_samples) if self.rssi_samples else -100.0

    @property
    def rssi_std(self) -> float:
        return statistics.stdev(self.rssi_samples) if len(self.rssi_samples) > 1 else 0.0

    @property
    def avg_beacon_interval(self) -> float:
        return statistics.mean(self.beacon_intervals) if self.beacon_intervals else 100.0

    @property
    def beacon_jitter(self) -> float:
        return statistics.stdev(self.beacon_intervals) if len(self.beacon_intervals) > 1 else 0.0

    def is_new_appearance(self, window_minutes: int) -> bool:
        return (time.time() - self.first_seen) < (window_minutes * 60)


@dataclass
class EvilTwinEvidence:
    """Evidence structure for an Evil Twin alert"""
    original_bssid: str
    suspect_bssid: str
    ssid: str

    # Feature values
    rssi_delta: float
    vendor_match: bool
    security_match: bool
    beacon_jitter_delta: float
    is_new_appearance: bool
    duplicate_count: int

    # Raw data
    original_profile: dict
    suspect_profile: dict

    # Samples
    sample_beacons: list[dict] = field(default_factory=list)
    ie_differences: list[str] = field(default_factory=list)

    # Sensor info
    sensor_ids: list[str] = field(default_factory=list)
    gps_coords: Optional[tuple[float, float]] = None


@dataclass
class EvilTwinAlert:
    """Alert output for Evil Twin detection"""
    alert_id: str
    timestamp: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    score: int
    confidence: float

    ssid: str
    original_bssid: str
    suspect_bssid: str

    mitre_technique: str
    mitre_tactic: str

    evidence: dict
    recommendation: str


# =============================================================================
# ADVANCED EVIL TWIN DETECTOR
# =============================================================================

class AdvancedEvilTwinDetector:
    """
    Advanced Evil Twin detector with weighted scoring model.

    Pipeline:
    1. Ingest telemetry
    2. Group by SSID
    3. Extract features
    4. Apply rules + scoring
    5. Temporal confirmation
    6. Emit alert with evidence
    """

    def __init__(self, config: Optional[EvilTwinConfig] = None):
        self.config = config or EvilTwinConfig()

        # State
        self.ap_profiles: dict[str, APProfile] = {}  # bssid -> profile
        self.ssid_to_bssids: dict[str, set[str]] = defaultdict(set)

        # Baseline (known-good APs)
        self.baseline_profiles: dict[str, APProfile] = {}

        # Pending alerts (for confirmation)
        self.pending_alerts: dict[str, dict] = {}  # key -> {alert, first_seen, count}

        # Stats
        self.alerts_generated = 0
        self._last_cleanup = time.time()

    def ingest(self, telemetry: dict[str, Any]) -> list[EvilTwinAlert]:
        """
        Process single telemetry record.

        Args:
            telemetry: Normalized telemetry record

        Returns:
            List of confirmed alerts
        """
        alerts = []

        # Extract fields
        bssid = telemetry.get('bssid', '').upper()
        ssid = telemetry.get('ssid')
        if not bssid or not ssid:
            return alerts

        # Update AP profile
        profile = self._update_profile(bssid, telemetry)

        # Track SSID mapping
        self.ssid_to_bssids[ssid].add(bssid)

        # Check for duplicates
        if len(self.ssid_to_bssids[ssid]) >= self.config.min_duplicate_count:
            # Evaluate all pairs
            for other_bssid in self.ssid_to_bssids[ssid]:
                if other_bssid == bssid:
                    continue

                other_profile = self.ap_profiles.get(other_bssid)
                if not other_profile:
                    continue

                # Determine which is "original" (older, more observations)
                if other_profile.observation_count > profile.observation_count:
                    original, suspect = other_profile, profile
                else:
                    original, suspect = profile, other_profile

                # Calculate score
                score, evidence = self._calculate_score(original, suspect)

                if score >= self.config.threshold_medium:
                    alert = self._handle_detection(original, suspect, score, evidence)
                    if alert:
                        alerts.append(alert)

        # Periodic cleanup
        self._cleanup()

        return alerts

    def _update_profile(self, bssid: str, telemetry: dict) -> APProfile:
        """Update or create AP profile"""
        now = time.time()

        if bssid in self.ap_profiles:
            profile = self.ap_profiles[bssid]
            profile.last_seen = now
            profile.observation_count += 1
        else:
            profile = APProfile(
                bssid=bssid,
                ssid=telemetry.get('ssid'),
                channel=telemetry.get('channel', 0),
                vendor_oui=telemetry.get('vendor_oui', bssid[:8]),
                security_type=self._parse_security(telemetry),
                rsn_capabilities=telemetry.get('rsn_info', {}),
                wpa_info=telemetry.get('wpa_info', {}),
                pmf_required=telemetry.get('capabilities', {}).get('pmf', False),
                wps_enabled=telemetry.get('capabilities', {}).get('wps', False),
                first_seen=now,
                last_seen=now,
                observation_count=1,
                ies_present=telemetry.get('ies_present', []),
                vendor_ies=telemetry.get('vendor_specific', [])
            )
            self.ap_profiles[bssid] = profile

        # Update metrics
        rssi = telemetry.get('rssi_dbm')
        if rssi is not None:
            profile.rssi_samples.append(rssi)
            if len(profile.rssi_samples) > 100:
                profile.rssi_samples = profile.rssi_samples[-100:]

        beacon = telemetry.get('beacon_interval')
        if beacon:
            profile.beacon_intervals.append(beacon)
            if len(profile.beacon_intervals) > 50:
                profile.beacon_intervals = profile.beacon_intervals[-50:]

        channel = telemetry.get('channel')
        if channel:
            profile.channels_seen.add(channel)

        sensor_id = telemetry.get('sensor_id')
        if sensor_id:
            profile.sensor_ids.add(sensor_id)

        return profile

    def _parse_security(self, telemetry: dict) -> str:
        """Parse security type from telemetry"""
        caps = telemetry.get('capabilities', {})
        rsn = telemetry.get('rsn_info', {})

        if not caps.get('privacy', False):
            return 'OPEN'
        if rsn.get('akm') and 'SAE' in str(rsn.get('akm', [])):
            return 'WPA3'
        if rsn:
            return 'WPA2'
        if telemetry.get('wpa_info'):
            return 'WPA'
        return 'WEP'

    def _calculate_score(
        self,
        original: APProfile,
        suspect: APProfile
    ) -> tuple[int, EvilTwinEvidence]:
        """
        Calculate Evil Twin score using weighted features.

        Returns:
            (score 0-100, evidence)
        """
        cfg = self.config
        score = 0

        # Feature: Duplicate SSID (always true at this point)
        dup_score = cfg.weight_duplicate_ssid
        score += dup_score

        # Feature: RSSI Delta
        rssi_delta = suspect.avg_rssi - original.avg_rssi
        if rssi_delta >= cfg.rssi_delta_threshold:
            # Scale: 0 at threshold, max at threshold+20dB
            rssi_factor = min(1.0, (rssi_delta - cfg.rssi_delta_threshold) / 20)
            score += int(cfg.weight_rssi_delta * rssi_factor)
        else:
            rssi_delta = 0  # Not significant

        # Feature: Vendor Mismatch
        vendor_match = original.vendor_oui.upper() == suspect.vendor_oui.upper()
        if not vendor_match:
            score += cfg.weight_vendor_mismatch

        # Feature: Security Mismatch
        security_match = original.security_type == suspect.security_type
        if not security_match:
            score += cfg.weight_security_mismatch

        # Feature: Beacon Jitter
        jitter_delta = abs(suspect.beacon_jitter - original.beacon_jitter)
        if jitter_delta > cfg.jitter_threshold_ms:
            jitter_factor = min(1.0, jitter_delta / 50)
            score += int(cfg.weight_beacon_jitter * jitter_factor)

        # Feature: New Appearance
        is_new = suspect.is_new_appearance(cfg.new_ap_window_minutes)
        if is_new:
            score += cfg.weight_new_appearance

        # Build evidence
        evidence = EvilTwinEvidence(
            original_bssid=original.bssid,
            suspect_bssid=suspect.bssid,
            ssid=original.ssid or suspect.ssid or "",
            rssi_delta=rssi_delta,
            vendor_match=vendor_match,
            security_match=security_match,
            beacon_jitter_delta=jitter_delta,
            is_new_appearance=is_new,
            duplicate_count=len(self.ssid_to_bssids.get(original.ssid, set())),
            original_profile={
                'bssid': original.bssid,
                'avg_rssi': original.avg_rssi,
                'security': original.security_type,
                'vendor': original.vendor_oui,
                'observations': original.observation_count,
                'channels': list(original.channels_seen)
            },
            suspect_profile={
                'bssid': suspect.bssid,
                'avg_rssi': suspect.avg_rssi,
                'security': suspect.security_type,
                'vendor': suspect.vendor_oui,
                'observations': suspect.observation_count,
                'first_seen': datetime.fromtimestamp(
                    suspect.first_seen, tz=timezone.utc
                ).isoformat()
            },
            sensor_ids=list(suspect.sensor_ids | original.sensor_ids),
            ie_differences=self._diff_ies(original, suspect)
        )

        return min(100, score), evidence

    def _diff_ies(self, original: APProfile, suspect: APProfile) -> list[str]:
        """Find IE differences between profiles"""
        diffs = []

        orig_ies = set(original.ies_present)
        susp_ies = set(suspect.ies_present)

        missing = orig_ies - susp_ies
        extra = susp_ies - orig_ies

        if missing:
            diffs.append(f"Missing IEs: {list(missing)}")
        if extra:
            diffs.append(f"Extra IEs: {list(extra)}")

        if original.wps_enabled != suspect.wps_enabled:
            diffs.append(f"WPS mismatch: orig={original.wps_enabled}, suspect={suspect.wps_enabled}")

        if original.pmf_required != suspect.pmf_required:
            diffs.append(f"PMF mismatch: orig={original.pmf_required}, suspect={suspect.pmf_required}")

        return diffs

    def _handle_detection(
        self,
        original: APProfile,
        suspect: APProfile,
        score: int,
        evidence: EvilTwinEvidence
    ) -> Optional[EvilTwinAlert]:
        """
        Handle detection with temporal confirmation.
        Require persistence to reduce transient FPs.
        """
        key = f"{original.bssid}:{suspect.bssid}"
        now = time.time()

        if key not in self.pending_alerts:
            # First detection - start confirmation window
            self.pending_alerts[key] = {
                'score': score,
                'evidence': evidence,
                'first_seen': now,
                'count': 1,
                'original': original.bssid,
                'suspect': suspect.bssid
            }

            # Immediate alert for critical score
            if score >= 90:
                return self._create_alert(score, evidence)

            return None

        else:
            # Update existing
            pending = self.pending_alerts[key]
            pending['count'] += 1
            pending['score'] = max(pending['score'], score)

            # Check confirmation window
            elapsed = now - pending['first_seen']
            if elapsed >= self.config.confirmation_window_seconds:
                # Confirmed - emit alert
                del self.pending_alerts[key]
                return self._create_alert(pending['score'], evidence)

            return None

    def _create_alert(self, score: int, evidence: EvilTwinEvidence) -> EvilTwinAlert:
        """Create final alert"""
        self.alerts_generated += 1

        # Determine severity
        if score >= self.config.threshold_critical:
            severity = "CRITICAL"
        elif score >= self.config.threshold_high:
            severity = "HIGH"
        elif score >= self.config.threshold_medium:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Confidence based on evidence completeness
        confidence_factors = [
            evidence.rssi_delta > 0,
            not evidence.vendor_match,
            not evidence.security_match,
            evidence.is_new_appearance,
            len(evidence.ie_differences) > 0
        ]
        confidence = sum(confidence_factors) / len(confidence_factors)

        return EvilTwinAlert(
            alert_id=f"ET-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alerts_generated:04d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            score=score,
            confidence=round(confidence, 2),
            ssid=evidence.ssid,
            original_bssid=evidence.original_bssid,
            suspect_bssid=evidence.suspect_bssid,
            mitre_technique=self.config.mitre_technique,
            mitre_tactic=self.config.mitre_tactic,
            evidence=asdict(evidence),
            recommendation=self._get_recommendation(severity, evidence)
        )

    def _get_recommendation(self, severity: str, evidence: EvilTwinEvidence) -> str:
        """Generate actionable recommendation"""
        if severity == "CRITICAL":
            return (
                f"IMMEDIATE ACTION: Potential Evil Twin detected on SSID '{evidence.ssid}'. "
                f"Suspect AP {evidence.suspect_bssid} shows {evidence.rssi_delta:.1f}dB stronger signal. "
                "Investigate on-site. Consider deauthenticating suspect AP if authorized."
            )
        elif severity == "HIGH":
            return (
                f"Investigate: Suspect AP {evidence.suspect_bssid} mimicking '{evidence.ssid}'. "
                "Cross-check with physical AP inventory. Monitor for client associations."
            )
        else:
            return (
                "Monitor: Unusual duplicate SSID detected. Review if legitimate roaming or guest AP."
            )

    def _cleanup(self):
        """Periodic cleanup of old data"""
        now = time.time()
        if now - self._last_cleanup < 60:
            return

        self._last_cleanup = now
        cutoff = now - (self.config.sliding_window_seconds * 2)

        # Remove old profiles
        stale = [
            bssid for bssid, profile in self.ap_profiles.items()
            if profile.last_seen < cutoff
        ]
        for bssid in stale:
            del self.ap_profiles[bssid]
            # Update SSID mapping
            for _, bssids in self.ssid_to_bssids.items():
                bssids.discard(bssid)

        # Remove empty SSID entries
        empty_ssids = [ssid for ssid, bssids in self.ssid_to_bssids.items() if not bssids]
        for ssid in empty_ssids:
            del self.ssid_to_bssids[ssid]

        # Expire pending alerts
        expired = [
            key for key, data in self.pending_alerts.items()
            if now - data['first_seen'] > self.config.sliding_window_seconds
        ]
        for key in expired:
            del self.pending_alerts[key]

    def add_baseline(self, bssid: str, profile: APProfile):
        """Add known-good AP to baseline (reduces FP)"""
        self.baseline_profiles[bssid.upper()] = profile

    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            'tracked_aps': len(self.ap_profiles),
            'tracked_ssids': len(self.ssid_to_bssids),
            'pending_alerts': len(self.pending_alerts),
            'alerts_generated': self.alerts_generated,
            'baseline_aps': len(self.baseline_profiles)
        }


# =============================================================================
# CLI / DEMO
# =============================================================================

def main():
    """Demo the advanced detector"""
    import json

    print("\n" + "=" * 60)
    print("ADVANCED EVIL TWIN DETECTOR DEMO")
    print("=" * 60)

    detector = AdvancedEvilTwinDetector()

    # Simulate legitimate AP (build history)
    print("\n[+] Building baseline for 'CorporateWiFi'...")
    for i in range(50):
        detector.ingest({
            'bssid': 'AA:BB:CC:11:22:33',
            'ssid': 'CorporateWiFi',
            'channel': 6,
            'rssi_dbm': -65 + (i % 5 - 2),  # Normal variation
            'vendor_oui': 'AA:BB:CC',
            'capabilities': {'privacy': True, 'pmf': True},
            'rsn_info': {'akm': ['PSK']},
            'beacon_interval': 100,
            'sensor_id': 'sensor-01'
        })

    print(f"    Tracked APs: {detector.get_stats()['tracked_aps']}")

    # Inject evil twin
    print("\n[!] Injecting Evil Twin AP...")
    alerts = detector.ingest({
        'bssid': 'DE:AD:BE:EF:00:01',
        'ssid': 'CorporateWiFi',  # Same SSID
        'channel': 6,
        'rssi_dbm': -35,  # Much stronger (attacker closer)
        'vendor_oui': 'DE:AD:BE',  # Different vendor!
        'capabilities': {'privacy': True, 'pmf': False},  # Different PMF
        'rsn_info': {'akm': ['PSK']},
        'beacon_interval': 102,
        'sensor_id': 'sensor-02',
        'ies_present': ['SSID', 'RSN']  # Missing some IEs
    })

    # Since confirmation window, simulate second observation
    time.sleep(0.1)
    for _ in range(3):
        alerts = detector.ingest({
            'bssid': 'DE:AD:BE:EF:00:01',
            'ssid': 'CorporateWiFi',
            'channel': 6,
            'rssi_dbm': -33,
            'vendor_oui': 'DE:AD:BE',
            'capabilities': {'privacy': True, 'pmf': False},
            'rsn_info': {'akm': ['PSK']},
            'beacon_interval': 105,
            'sensor_id': 'sensor-02'
        })

    # Force confirmation with high score
    # In real scenario, this happens after confirmation_window_seconds
    detector.config.confirmation_window_seconds = 0  # Bypass for demo
    alerts = detector.ingest({
        'bssid': 'DE:AD:BE:EF:00:01',
        'ssid': 'CorporateWiFi',
        'channel': 6,
        'rssi_dbm': -30,
        'vendor_oui': 'DE:AD:BE',
        'capabilities': {'privacy': True, 'pmf': False},
        'sensor_id': 'sensor-02'
    })

    if alerts:
        for alert in alerts:
            print(f"\n⚠️  ALERT: {alert.severity}")
            print(f"    ID: {alert.alert_id}")
            print(f"    Score: {alert.score}/100")
            print(f"    SSID: {alert.ssid}")
            print(f"    Original: {alert.original_bssid}")
            print(f"    Suspect: {alert.suspect_bssid}")
            print(f"    MITRE: {alert.mitre_technique}")
            print(f"    Recommendation: {alert.recommendation[:80]}...")
    else:
        print("    (Alert pending confirmation...)")

    print(f"\n[+] Stats: {json.dumps(detector.get_stats(), indent=2)}")


if __name__ == '__main__':
    main()
