"""
Unit tests for PMKID Harvesting Attack Detector.
"""

import pytest

from algos.pmkid_detector import PMKIDAttackDetector, PMKIDConfig


@pytest.fixture
def detector():
    """Detector with low thresholds for fast testing."""
    return PMKIDAttackDetector(
        config=PMKIDConfig(
            eapol_m1_threshold=5,
            eapol_time_window=10,
            auth_flood_threshold=10,
            auth_time_window=5,
            min_unique_sources=3,
            cooldown_seconds=1,
        )
    )


BSSID = "AA:BB:CC:DD:EE:FF"


# ─── EAPOL M1 Detection ──────────────────────────────────────────────────


def test_no_alert_below_m1_threshold(detector):
    """Feed fewer M1 frames than threshold → no alert."""
    for _ in range(4):  # threshold is 5
        result = detector.ingest(
            {"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1}
        )
    assert result is None


def test_alert_on_eapol_m1_flood(detector):
    """Feed >= threshold M1 frames with no M2 → alert fires."""
    alerts = []
    for _ in range(6):
        result = detector.ingest(
            {"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1}
        )
        if result:
            alerts.append(result)
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert["alert_type"] == "pmkid_harvesting"
    assert alert["severity"] in ("HIGH", "CRITICAL")
    assert alert["bssid"] == BSSID
    assert "EAPOL_M1_FLOOD" in alert["evidence"]["indicators"]


def test_m2_reduces_orphan_count(detector):
    """If M2 arrives after M1, the M1 is no longer orphaned."""
    # Send 4 M1s
    for _ in range(4):
        detector.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
    # Send 2 M2s (pairs 2 of the 4 M1s)
    for _ in range(2):
        detector.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 2})
    # Now only 2 orphaned M1s remain — below threshold of 5
    result = detector.ingest(
        {"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1}
    )
    assert result is None  # 3 orphans < 5 threshold


# ─── Auth Flood Detection ────────────────────────────────────────────────


def test_auth_flood_from_diverse_macs(detector):
    """Auth flood from many unique MACs triggers alert."""
    alerts = []
    for i in range(12):
        result = detector.ingest(
            {
                "frame_type": "auth",
                "bssid": BSSID,
                "src_addr": f"DE:AD:BE:EF:00:{i:02X}",
            }
        )
        if result:
            alerts.append(result)
    assert len(alerts) >= 1
    assert "AUTH_FLOOD_RANDOM_MAC" in alerts[0]["evidence"]["indicators"]


def test_auth_flood_same_mac_no_alert(detector):
    """Auth flood from a single MAC (not random) → no alert (unique < threshold)."""
    for _ in range(15):
        result = detector.ingest(
            {
                "frame_type": "auth",
                "bssid": BSSID,
                "src_addr": "DE:AD:BE:EF:00:01",
            }
        )
    # unique_sources = 1, below min_unique_sources (3)
    assert result is None


# ─── Combined Detection ──────────────────────────────────────────────────


def test_combined_critical_severity():
    """Auth flood + M1 flood together → CRITICAL severity."""
    # Strategy: bring both counters just below threshold, then
    # push both over at the same frame.
    det = PMKIDAttackDetector(
        config=PMKIDConfig(
            eapol_m1_threshold=3,
            eapol_time_window=10,
            auth_flood_threshold=6,  # threshold 6, we'll send 5 first
            auth_time_window=10,
            min_unique_sources=3,
            cooldown_seconds=60,
        )
    )
    # Send 5 auth frames (below threshold of 6) — no alert
    for i in range(5):
        r = det.ingest(
            {
                "frame_type": "auth",
                "bssid": BSSID,
                "src_addr": f"DE:AD:BE:EF:00:{i:02X}",
            }
        )
        assert r is None

    # Send 2 M1 frames (below threshold of 3) — no alert
    for _ in range(2):
        r = det.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
        assert r is None

    # Push auth to threshold=6
    det.ingest({"frame_type": "auth", "bssid": BSSID, "src_addr": "DE:AD:BE:EF:00:05"})
    # Auth fired HIGH alert → clear cooldown
    det.last_alert_time.clear()

    # Send M1 #3 — pushes eapol to threshold=3 while auth stays at 6
    result = det.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
    assert result is not None
    assert result["severity"] == "CRITICAL"
    assert "EAPOL_M1_FLOOD" in result["evidence"]["indicators"]
    assert "AUTH_FLOOD_RANDOM_MAC" in result["evidence"]["indicators"]


# ─── Cooldown ─────────────────────────────────────────────────────────────


def test_cooldown_prevents_duplicate_alerts(detector):
    """After alert fires, cooldown prevents immediate re-alerting."""
    # Trigger alert
    for _ in range(6):
        detector.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
    # Try again immediately — should be suppressed
    result = detector.ingest(
        {"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1}
    )
    assert result is None


# ─── Irrelevant Frames ───────────────────────────────────────────────────


def test_ignores_data_frames(detector):
    """Data frames should not trigger anything."""
    for _ in range(20):
        result = detector.ingest({"frame_type": "data", "bssid": BSSID})
    assert result is None


def test_ignores_empty_bssid(detector):
    """Frames without BSSID are ignored."""
    result = detector.ingest({"frame_type": "eapol", "bssid": "", "eapol_message": 1})
    assert result is None


# ─── Stats & Reset ────────────────────────────────────────────────────────


def test_get_stats(detector):
    """Stats should reflect tracked state."""
    detector.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
    stats = detector.get_stats()
    assert stats["tracked_aps"] == 1
    assert stats["alerts_generated"] == 0


def test_reset(detector):
    """Reset clears all state."""
    detector.ingest({"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1})
    detector.reset()
    assert detector.get_stats()["tracked_aps"] == 0


# ─── Alert Content Validation ────────────────────────────────────────────


def test_alert_has_required_fields(detector):
    """Alert dict must contain all standard fields."""
    alerts = []
    for _ in range(6):
        result = detector.ingest(
            {"frame_type": "eapol", "bssid": BSSID, "eapol_message": 1}
        )
        if result:
            alerts.append(result)

    assert len(alerts) >= 1
    alert = alerts[0]
    required_keys = [
        "alert_type",
        "severity",
        "title",
        "description",
        "bssid",
        "timestamp",
        "evidence",
        "mitre_attack",
        "action_recommended",
    ]
    for key in required_keys:
        assert key in alert, f"Missing key: {key}"

    assert alert["mitre_attack"] == "T1110.002"


# ─── Multiple APs ────────────────────────────────────────────────────────


def test_independent_ap_tracking(detector):
    """Each AP is tracked independently."""
    bssid_a = "11:11:11:11:11:11"
    bssid_b = "22:22:22:22:22:22"

    # Flood AP A only
    for _ in range(6):
        detector.ingest({"frame_type": "eapol", "bssid": bssid_a, "eapol_message": 1})

    # AP B should not be alerted
    result = detector.ingest(
        {"frame_type": "eapol", "bssid": bssid_b, "eapol_message": 1}
    )
    assert result is None
    assert detector.get_stats()["tracked_aps"] == 2
