#!/usr/bin/env python3
"""
Golden PCAP Regression Tests
-----------------------------
Replays annotated PCAPs through detectors and verifies expected alerts.
Uses manifests to compare detector output against ground truth labels.

Run with: pytest tests/detectors/test_pcap_regression.py -v
"""
import json
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from algos.evil_twin import AdvancedEvilTwinDetector, EvilTwinConfig
from algos.dos import DeauthFloodDetector

# Paths
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "pcap_annotated"


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def evil_twin_detector():
    """Create Evil Twin detector with fast confirmation for testing."""
    config = EvilTwinConfig(
        confirmation_window_seconds=0,  # Immediate alerts for testing
        min_duplicate_count=2,
    )
    return AdvancedEvilTwinDetector(config)


@pytest.fixture
def dos_detector():
    """Create DoS detector with test-friendly settings."""
    return DeauthFloodDetector(
        threshold_per_sec=5.0,
        window_seconds=1.0,
        cooldown_seconds=0.0,  # No cooldown for testing
    )


@pytest.fixture
def evil_twin_manifest():
    """Load evil twin manifest."""
    manifest_path = DATA_DIR / "sample_evil_twin_manifest.json"
    if not manifest_path.exists():
        pytest.skip(f"Manifest not found: {manifest_path}")
    with open(manifest_path) as f:
        return json.load(f)


@pytest.fixture
def deauth_manifest():
    """Load deauth manifest."""
    manifest_path = DATA_DIR / "sample_deauth_manifest.json"
    if not manifest_path.exists():
        pytest.skip(f"Manifest not found: {manifest_path}")
    with open(manifest_path) as f:
        return json.load(f)


@pytest.fixture
def benign_manifest():
    """Load benign manifest."""
    manifest_path = DATA_DIR / "sample_benign_manifest.json"
    if not manifest_path.exists():
        pytest.skip(f"Manifest not found: {manifest_path}")
    with open(manifest_path) as f:
        return json.load(f)


# =============================================================================
# EVIL TWIN TESTS
# =============================================================================


class TestEvilTwinRegression:
    """Regression tests for Evil Twin detector using golden PCAPs."""

    def test_detects_evil_twin_from_manifest(
        self, evil_twin_detector, evil_twin_manifest
    ):
        """
        Replay evil twin manifest and verify detector fires.
        Expected: At least one alert with SSID 'CorpNet'.
        """
        annotations = evil_twin_manifest.get("annotations", [])
        alerts = []

        for ann in annotations:
            # Convert annotation to telemetry format
            telemetry = {
                "bssid": ann.get("bssid", "").upper(),
                "ssid": ann.get("ssid"),
                "channel": 6,
                "rssi_dbm": -50 if ann.get("label") == "evil_twin" else -70,
                "vendor_oui": ann.get("bssid", "")[:8].upper(),
                "sensor_id": "test-sensor",
            }

            result = evil_twin_detector.ingest(telemetry)
            if result:
                alerts.extend(result)

        # Assertions
        assert len(alerts) >= 1, "Expected at least one Evil Twin alert"
        
        # Verify alert quality
        alert = alerts[0]
        assert alert.ssid == "CorpNet", f"Expected SSID 'CorpNet', got '{alert.ssid}'"
        assert "DUPLICATE_SSID" in alert.reason_codes
        assert alert.severity in ["MEDIUM", "HIGH", "CRITICAL"]

    def test_no_false_positives_on_benign(
        self, evil_twin_detector, benign_manifest
    ):
        """
        Replay benign manifest and verify NO alerts fire.
        Expected: Zero alerts.
        """
        annotations = benign_manifest.get("annotations", [])
        alerts = []

        for ann in annotations:
            telemetry = {
                "bssid": ann.get("bssid", "").upper(),
                "ssid": ann.get("ssid"),
                "channel": ann.get("channel", 6),
                "rssi_dbm": -65,
                "vendor_oui": ann.get("bssid", "")[:8].upper(),
                "sensor_id": "test-sensor",
            }

            result = evil_twin_detector.ingest(telemetry)
            if result:
                alerts.extend(result)

        # Assertion: No false positives
        assert len(alerts) == 0, f"Expected zero alerts on benign data, got {len(alerts)}"


# =============================================================================
# DEAUTH FLOOD TESTS
# =============================================================================


class TestDeauthFloodRegression:
    """Regression tests for Deauth Flood detector using golden PCAPs."""

    def test_detects_deauth_flood_from_manifest(
        self, dos_detector, deauth_manifest
    ):
        """
        Replay deauth manifest and verify detector fires.
        Expected: At least one alert.
        """
        annotations = deauth_manifest.get("annotations", [])
        alerts = []

        for ann in annotations:
            if ann.get("frame_type") == "deauth":
                bssid = ann.get("bssid", "00:00:00:00:00:00").upper()
                client = ann.get("target_client", "ff:ff:ff:ff:ff:ff").upper()
                
                result = dos_detector.record_deauth(bssid, client, "test-sensor")
                if result:
                    alerts.append(result)

        # Assertions
        assert len(alerts) >= 1, "Expected at least one Deauth Flood alert"
        
        # Verify alert quality
        alert = alerts[0]
        assert "DEAUTH_FLOOD" in alert.reason_codes
        assert alert.severity in ["MEDIUM", "HIGH", "CRITICAL"]


# =============================================================================
# SUMMARY / STATS
# =============================================================================


class TestManifestIntegrity:
    """Tests to verify manifest files are valid and complete."""

    @pytest.mark.parametrize(
        "manifest_name",
        [
            "sample_evil_twin_manifest.json",
            "sample_deauth_manifest.json",
            "sample_benign_manifest.json",
        ],
    )
    def test_manifest_has_required_fields(self, manifest_name):
        """Verify manifests have required structure."""
        manifest_path = DATA_DIR / manifest_name
        if not manifest_path.exists():
            pytest.skip(f"Manifest not found: {manifest_path}")

        with open(manifest_path) as f:
            data = json.load(f)

        assert "pcap_file" in data, "Missing 'pcap_file' field"
        assert "annotations" in data, "Missing 'annotations' field"
        assert len(data["annotations"]) > 0, "No annotations in manifest"
