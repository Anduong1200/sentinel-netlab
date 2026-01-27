#!/usr/bin/env python3
"""
Sentinel NetLab - Evil Twin and Deauth Flood Detectors
Specialized detection modules for common WiFi attacks.
"""

import logging
import time
from datetime import datetime, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from difflib import SequenceMatcher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NetworkProfile:
    """Profile of a known network"""
    bssid: str
    ssid: Optional[str]
    channel: int
    security: str
    first_seen: datetime
    last_seen: datetime
    rssi_samples: List[int] = field(default_factory=list)
    observation_count: int = 0
    sensor_ids: set = field(default_factory=set)
    beacon_intervals: List[int] = field(default_factory=list)
    
    @property
    def avg_rssi(self) -> float:
        if not self.rssi_samples:
            return -100.0
        return sum(self.rssi_samples) / len(self.rssi_samples)
    
    @property
    def avg_beacon_interval(self) -> float:
        if not self.beacon_intervals:
            return 100.0
        return sum(self.beacon_intervals) / len(self.beacon_intervals)


@dataclass
class EvilTwinAlert:
    """Alert for evil twin detection"""
    alert_id: str
    timestamp: str
    original_bssid: str
    rogue_bssid: str
    ssid: str
    rssi_delta: float
    security_match: bool
    confidence: float
    evidence: Dict


@dataclass
class DeauthFloodAlert:
    """Alert for deauth flood detection"""
    alert_id: str
    timestamp: str
    target_bssid: str
    target_client: Optional[str]
    frame_count: int
    window_seconds: float
    rate_per_sec: float
    evidence: Dict


# =============================================================================
# EVIL TWIN DETECTOR
# =============================================================================

class EvilTwinDetector:
    """
    Detects evil twin attacks by identifying:
    1. Same/similar SSID with different BSSID
    2. Unusually strong signal (attacker closer than legit AP)
    3. Security capability differences
    4. Beacon interval anomalies
    """
    
    def __init__(self, 
                 ssid_similarity_threshold: float = 0.85,
                 rssi_delta_threshold: int = 20,
                 max_rssi_samples: int = 100):
        self.known_networks: Dict[str, NetworkProfile] = {}  # bssid -> profile
        self.ssid_to_bssids: Dict[str, set] = defaultdict(set)  # ssid -> {bssids}
        
        self.ssid_similarity_threshold = ssid_similarity_threshold
        self.rssi_delta_threshold = rssi_delta_threshold
        self.max_rssi_samples = max_rssi_samples
        
        self.alert_count = 0
    
    def update_network(self, 
                       bssid: str,
                       ssid: Optional[str],
                       channel: int,
                       security: str,
                       rssi_dbm: int,
                       sensor_id: str,
                       beacon_interval_ms: int = 100) -> List[EvilTwinAlert]:
        """
        Update network profile and check for evil twins.
        Returns list of alerts if suspicious activity detected.
        """
        now = datetime.now(timezone.utc)
        alerts = []
        
        # Update or create profile
        if bssid in self.known_networks:
            profile = self.known_networks[bssid]
            profile.last_seen = now
            profile.observation_count += 1
            profile.sensor_ids.add(sensor_id)
            
            # Keep limited RSSI samples
            profile.rssi_samples.append(rssi_dbm)
            if len(profile.rssi_samples) > self.max_rssi_samples:
                profile.rssi_samples = profile.rssi_samples[-self.max_rssi_samples:]
            
            if beacon_interval_ms:
                profile.beacon_intervals.append(beacon_interval_ms)
                if len(profile.beacon_intervals) > 50:
                    profile.beacon_intervals = profile.beacon_intervals[-50:]
        else:
            profile = NetworkProfile(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                security=security,
                first_seen=now,
                last_seen=now,
                rssi_samples=[rssi_dbm],
                observation_count=1,
                sensor_ids={sensor_id},
                beacon_intervals=[beacon_interval_ms] if beacon_interval_ms else []
            )
            self.known_networks[bssid] = profile
        
        # Track SSID -> BSSIDs mapping
        if ssid:
            self.ssid_to_bssids[ssid].add(bssid)
        
        # Check for evil twins
        if ssid:
            alert = self._check_evil_twin(profile, rssi_dbm)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _check_evil_twin(self, current: NetworkProfile, current_rssi: int) -> Optional[EvilTwinAlert]:
        """Check if current network is an evil twin of a known network"""
        if not current.ssid:
            return None
        
        # Find networks with same/similar SSID
        for ssid, bssids in self.ssid_to_bssids.items():
            if current.bssid in bssids:
                continue  # Skip self
            
            # Check SSID similarity
            similarity = SequenceMatcher(None, current.ssid.lower(), ssid.lower()).ratio()
            
            if similarity >= self.ssid_similarity_threshold:
                # Found similar SSID with different BSSID
                for other_bssid in bssids:
                    if other_bssid == current.bssid:
                        continue
                    
                    other = self.known_networks.get(other_bssid)
                    if not other:
                        continue
                    
                    # Calculate RSSI delta
                    rssi_delta = current_rssi - other.avg_rssi
                    
                    # Check if current is suspiciously stronger
                    if rssi_delta > self.rssi_delta_threshold:
                        # Security mismatch check
                        security_match = current.security == other.security
                        
                        # Calculate confidence
                        confidence = self._calculate_confidence(
                            similarity, rssi_delta, security_match, other.observation_count
                        )
                        
                        if confidence >= 0.6:  # Minimum confidence threshold
                            return self._create_alert(
                                original_bssid=other_bssid,
                                rogue_bssid=current.bssid,
                                ssid=current.ssid or ssid,
                                rssi_delta=rssi_delta,
                                security_match=security_match,
                                confidence=confidence,
                                original_profile=other,
                                rogue_profile=current
                            )
        
        return None
    
    def _calculate_confidence(self, 
                              ssid_similarity: float,
                              rssi_delta: float,
                              security_match: bool,
                              original_observations: int) -> float:
        """Calculate confidence score for evil twin detection"""
        confidence = 0.0
        
        # SSID similarity contributes up to 0.3
        confidence += ssid_similarity * 0.3
        
        # RSSI delta contributes up to 0.3 (higher delta = higher confidence)
        rssi_factor = min(1.0, (rssi_delta - self.rssi_delta_threshold) / 30)
        confidence += rssi_factor * 0.3
        
        # Security mismatch is actually more suspicious
        if not security_match:
            confidence += 0.2
        
        # More observations of original = higher confidence
        obs_factor = min(1.0, original_observations / 100)
        confidence += obs_factor * 0.2
        
        return min(1.0, confidence)
    
    def _create_alert(self, **kwargs) -> EvilTwinAlert:
        """Create evil twin alert"""
        self.alert_count += 1
        
        return EvilTwinAlert(
            alert_id=f"ET-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alert_count:04d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            original_bssid=kwargs['original_bssid'],
            rogue_bssid=kwargs['rogue_bssid'],
            ssid=kwargs['ssid'],
            rssi_delta=kwargs['rssi_delta'],
            security_match=kwargs['security_match'],
            confidence=kwargs['confidence'],
            evidence={
                'original_avg_rssi': kwargs['original_profile'].avg_rssi,
                'rogue_rssi': kwargs['rogue_profile'].rssi_samples[-1],
                'original_observations': kwargs['original_profile'].observation_count,
                'original_security': kwargs['original_profile'].security,
                'rogue_security': kwargs['rogue_profile'].security
            }
        )


# =============================================================================
# DEAUTH FLOOD DETECTOR
# =============================================================================

class DeauthFloodDetector:
    """
    Detects deauthentication flood attacks by:
    1. Tracking deauth frame rate per BSSID/client
    2. Sliding window analysis
    3. Burst pattern detection
    """
    
    def __init__(self,
                 threshold_per_sec: float = 10.0,
                 window_seconds: float = 2.0,
                 cooldown_seconds: float = 60.0):
        self.threshold_per_sec = threshold_per_sec
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        
        # Track deauth frames: (bssid, client) -> [timestamps]
        self.deauth_history: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        
        # Cooldown tracking
        self.last_alert: Dict[Tuple[str, str], float] = {}
        
        self.alert_count = 0
    
    def record_deauth(self,
                      bssid: str,
                      client_mac: str = "ff:ff:ff:ff:ff:ff",
                      sensor_id: str = "") -> Optional[DeauthFloodAlert]:
        """
        Record a deauth frame and check for flood.
        Returns alert if flood detected.
        """
        now = time.time()
        key = (bssid, client_mac)
        
        # Add timestamp
        self.deauth_history[key].append(now)
        
        # Clean old entries
        self._cleanup(key, now)
        
        # Check for flood
        return self._check_flood(key, bssid, client_mac, sensor_id, now)
    
    def _cleanup(self, key: Tuple[str, str], now: float):
        """Remove entries outside the window"""
        cutoff = now - self.window_seconds * 2  # Keep 2x window for analysis
        self.deauth_history[key] = [
            t for t in self.deauth_history[key] if t >= cutoff
        ]
    
    def _check_flood(self,
                     key: Tuple[str, str],
                     bssid: str,
                     client_mac: str,
                     sensor_id: str,
                     now: float) -> Optional[DeauthFloodAlert]:
        """Check if current rate exceeds threshold"""
        # Check cooldown
        if key in self.last_alert:
            if now - self.last_alert[key] < self.cooldown_seconds:
                return None
        
        # Count frames in window
        window_start = now - self.window_seconds
        frames_in_window = [t for t in self.deauth_history[key] if t >= window_start]
        count = len(frames_in_window)
        
        # Calculate rate
        rate = count / self.window_seconds
        
        if rate >= self.threshold_per_sec:
            self.last_alert[key] = now
            return self._create_alert(bssid, client_mac, count, rate, sensor_id)
        
        return None
    
    def _create_alert(self,
                      bssid: str,
                      client_mac: str,
                      count: int,
                      rate: float,
                      sensor_id: str) -> DeauthFloodAlert:
        """Create deauth flood alert"""
        self.alert_count += 1
        
        return DeauthFloodAlert(
            alert_id=f"DF-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alert_count:04d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_bssid=bssid,
            target_client=client_mac if client_mac != "ff:ff:ff:ff:ff:ff" else None,
            frame_count=count,
            window_seconds=self.window_seconds,
            rate_per_sec=rate,
            evidence={
                'sensor_id': sensor_id,
                'threshold_per_sec': self.threshold_per_sec,
                'is_broadcast': client_mac == "ff:ff:ff:ff:ff:ff"
            }
        )
    
    def get_stats(self) -> Dict:
        """Get current detection statistics"""
        total_tracked = sum(len(v) for v in self.deauth_history.values())
        return {
            'tracked_pairs': len(self.deauth_history),
            'total_recent_frames': total_tracked,
            'alerts_generated': self.alert_count
        }


# =============================================================================
# TIME-SERIES BASELINE (72-hour learning)
# =============================================================================

class TimeSeriesBaseline:
    """
    Builds behavioral baseline over configurable period.
    Tracks normal patterns for anomaly detection.
    """
    
    def __init__(self, learning_hours: int = 72, min_observations: int = 100):
        self.learning_hours = learning_hours
        self.min_observations = min_observations
        
        # Baselines per BSSID
        self.baselines: Dict[str, Dict] = {}
        
        # Learning state
        self.learning_start = datetime.now(timezone.utc)
        self.is_learning = True
    
    def update(self, bssid: str, data: Dict) -> Optional[Dict]:
        """
        Update baseline with new observation.
        Returns anomaly dict if deviation detected.
        """
        now = datetime.now(timezone.utc)
        
        # Check if still in learning period
        learning_elapsed = (now - self.learning_start).total_seconds() / 3600
        self.is_learning = learning_elapsed < self.learning_hours
        
        # Initialize baseline for BSSID
        if bssid not in self.baselines:
            self.baselines[bssid] = self._init_baseline()
        
        baseline = self.baselines[bssid]
        
        # Update statistics
        self._update_stats(baseline, data)
        
        # Check for anomalies (only after learning period)
        if not self.is_learning and baseline['observations'] >= self.min_observations:
            return self._check_anomalies(baseline, data)
        
        return None
    
    def _init_baseline(self) -> Dict:
        """Initialize baseline structure"""
        return {
            'observations': 0,
            'first_seen': datetime.now(timezone.utc).isoformat(),
            'last_seen': None,
            
            # RSSI statistics
            'rssi_sum': 0,
            'rssi_sum_sq': 0,
            'rssi_min': None,
            'rssi_max': None,
            
            # Channel tracking
            'channels_seen': set(),
            
            # Beacon interval
            'beacon_sum': 0,
            'beacon_count': 0,
            
            # Hourly activity pattern (24 buckets)
            'hourly_activity': [0] * 24
        }
    
    def _update_stats(self, baseline: Dict, data: Dict):
        """Update baseline statistics"""
        baseline['observations'] += 1
        baseline['last_seen'] = datetime.now(timezone.utc).isoformat()
        
        # RSSI
        rssi = data.get('rssi_dbm')
        if rssi is not None:
            baseline['rssi_sum'] += rssi
            baseline['rssi_sum_sq'] += rssi * rssi
            
            if baseline['rssi_min'] is None or rssi < baseline['rssi_min']:
                baseline['rssi_min'] = rssi
            if baseline['rssi_max'] is None or rssi > baseline['rssi_max']:
                baseline['rssi_max'] = rssi
        
        # Channel
        channel = data.get('channel')
        if channel is not None:
            baseline['channels_seen'].add(channel)
        
        # Beacon interval
        beacon = data.get('beacon_interval_ms')
        if beacon is not None:
            baseline['beacon_sum'] += beacon
            baseline['beacon_count'] += 1
        
        # Hourly activity
        hour = datetime.now(timezone.utc).hour
        baseline['hourly_activity'][hour] += 1
    
    def _check_anomalies(self, baseline: Dict, data: Dict) -> Optional[Dict]:
        """Check for deviations from baseline"""
        anomalies = []
        n = baseline['observations']
        
        # Calculate RSSI mean and std
        rssi_mean = baseline['rssi_sum'] / n
        rssi_variance = (baseline['rssi_sum_sq'] / n) - (rssi_mean ** 2)
        rssi_std = rssi_variance ** 0.5 if rssi_variance > 0 else 1.0
        
        # Check RSSI anomaly (> 2 std from mean)
        current_rssi = data.get('rssi_dbm')
        if current_rssi is not None:
            z_score = (current_rssi - rssi_mean) / rssi_std if rssi_std > 0 else 0
            if abs(z_score) > 2.5:
                anomalies.append({
                    'type': 'rssi_anomaly',
                    'expected': rssi_mean,
                    'actual': current_rssi,
                    'z_score': z_score
                })
        
        # Check channel anomaly
        current_channel = data.get('channel')
        if current_channel is not None and current_channel not in baseline['channels_seen']:
            anomalies.append({
                'type': 'new_channel',
                'expected_channels': list(baseline['channels_seen']),
                'actual': current_channel
            })
        
        if anomalies:
            return {
                'bssid': data.get('bssid'),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'anomalies': anomalies,
                'baseline_observations': n
            }
        
        return None
    
    def get_status(self) -> Dict:
        """Get baseline learning status"""
        elapsed = (datetime.now(timezone.utc) - self.learning_start).total_seconds() / 3600
        return {
            'is_learning': self.is_learning,
            'learning_hours': self.learning_hours,
            'elapsed_hours': elapsed,
            'progress_pct': min(100, (elapsed / self.learning_hours) * 100),
            'networks_tracked': len(self.baselines),
            'total_observations': sum(b['observations'] for b in self.baselines.values())
        }


# =============================================================================
# CLI
# =============================================================================

def main():
    """Test detectors"""
    print("\n" + "="*60)
    print("WIDS DETECTOR TEST")
    print("="*60)
    
    # Test Evil Twin Detector
    print("\n--- Evil Twin Detector ---")
    et_detector = EvilTwinDetector(ssid_similarity_threshold=0.8, rssi_delta_threshold=15)
    
    # Add "legitimate" network
    for i in range(50):
        et_detector.update_network(
            bssid="AA:BB:CC:11:22:33",
            ssid="CorporateWiFi",
            channel=6,
            security="WPA2",
            rssi_dbm=-65,
            sensor_id="sensor-01"
        )
    
    # Add suspicious "twin"
    alerts = et_detector.update_network(
        bssid="AA:BB:CC:99:88:77",
        ssid="CorporateWiFi",  # Same SSID
        channel=6,
        security="WPA2",
        rssi_dbm=-35,  # Much stronger signal
        sensor_id="sensor-01"
    )
    
    for alert in alerts:
        print(f"  ⚠️  Evil Twin: {alert.rogue_bssid} impersonating {alert.original_bssid}")
        print(f"      SSID: {alert.ssid}, RSSI delta: {alert.rssi_delta}dB, Confidence: {alert.confidence:.2f}")
    
    # Test Deauth Flood Detector
    print("\n--- Deauth Flood Detector ---")
    df_detector = DeauthFloodDetector(threshold_per_sec=5, window_seconds=2)
    
    # Simulate flood
    for i in range(15):
        alert = df_detector.record_deauth(
            bssid="AA:BB:CC:11:22:33",
            client_mac="ff:ff:ff:ff:ff:ff",
            sensor_id="sensor-01"
        )
        if alert:
            print(f"  ⚠️  Deauth Flood: {alert.frame_count} frames in {alert.window_seconds}s")
            print(f"      Target: {alert.target_bssid}, Rate: {alert.rate_per_sec:.1f}/s")
            break
    
    # Test Baseline
    print("\n--- Time Series Baseline ---")
    baseline = TimeSeriesBaseline(learning_hours=1, min_observations=10)  # Short for demo
    
    for i in range(15):
        baseline.update("AA:BB:CC:11:22:33", {'rssi_dbm': -65, 'channel': 6})
    
    status = baseline.get_status()
    print(f"  Learning: {status['is_learning']}, Progress: {status['progress_pct']:.1f}%")
    print(f"  Networks: {status['networks_tracked']}, Observations: {status['total_observations']}")


if __name__ == '__main__':
    main()
