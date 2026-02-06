
from datetime import UTC, datetime, timedelta
from typing import Any

from controller.baseline.models import BaselineProfile
from controller.baseline.store import BaselineStore


class BaselineBuilder:
    """
    Logic to aggregate telemetry into baseline profiles.
    """

    def __init__(self, store: BaselineStore, min_duration: timedelta = timedelta(days=3), min_samples: int = 100):
        self.store = store
        self.min_duration = min_duration
        self.min_samples = min_samples

    def update_from_telemetry(self, site_id: str, telemetry_batch: list[dict[str, Any]]):
        """
        Process a batch of telemetry and update relevant baselines.
        """
        for item in telemetry_batch:
            # Determine Network Key
            # Strategy: Baseline by SSID + Security Mode (Logical Network)
            # Or by BSSID (Physical AP).
            # For this phase, let's track by SSID+Security as primary key for "Network Profile"
            ssid = item.get("ssid")
            security = item.get("security")
            # bssid = item.get("bssid") # Unused

            if not ssid:
                continue # Skip hidden/probe requests without SSID for logical baseline

            network_key = f"{ssid}|{security}"

            profile = self.store.get_or_create_profile(site_id, network_key)
            self._update_profile_stats(profile, item)
            self.store.update_profile(profile)

    def _update_profile_stats(self, profile: BaselineProfile, item: dict[str, Any]):
        """In-place update of profile features."""
        features = dict(profile.features) # Copy for mutability if needed

        # 1. Channels
        channel = str(item.get("channel", "unknown"))
        channels = features.get("channels", {})
        channels[channel] = channels.get(channel, 0) + 1
        features["channels"] = channels

        # 2. RSSI
        rssi = item.get("rssi_dbm")
        if rssi is not None:
            r_stats = features.get("rssi", {"min": 999, "max": -999, "sum": 0, "count": 0})
            r_stats["min"] = min(r_stats["min"], rssi)
            r_stats["max"] = max(r_stats["max"], rssi)
            r_stats["sum"] += rssi
            r_stats["count"] += 1
            features["rssi"] = r_stats

        # 3. Vendors (OUI)
        # Simplified: just track full BSSID count or a vendor field if available
        # features["vendors"]...

        profile.features = features
        profile.sample_count += 1

    def is_warmed_up(self, profile: BaselineProfile) -> bool:
        """
        Check if profile has enough data to be trusted.
        Criteria: > 3 days age AND > 100 samples.
        """
        if not profile.first_seen:
            return False

        age = datetime.now(UTC) - profile.first_seen
        is_old_enough = age > self.min_duration
        has_samples = profile.sample_count > self.min_samples

        return is_old_enough and has_samples
