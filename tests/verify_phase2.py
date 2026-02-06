
import os

# Adjust path for imports
import sys
import time

sys.path.append(os.getcwd())

from algos.risk import EnhancedRiskScorer
from sensor.alert_manager import AlertManager
from sensor.baseline import BaselineManager

DB_PATH = "data/test_baseline.db"

def cleanup():
    if os.path.exists("data"):
         if os.path.exists(DB_PATH):
             try: os.remove(DB_PATH)
             except: pass
         try: os.remove(DB_PATH + "-wal")
         except: pass
         try: os.remove(DB_PATH + "-shm")
         except: pass

def test_phase2():
    print("=== Phase 2 Verification ===")
    cleanup()

    # 1. Baseline Learning
    print("[1] Testing Baseline Learning...")
    bm = BaselineManager(db_path=DB_PATH)
    bm.set_learning_mode(True)

    # Simulate learning normal traffic
    normal_frame = {
        "bssid": "00:11:22:33:44:55",
        "ssid": "MyCorp",
        "vendor_oui": "Intel",
        "rssi_dbm": -60,
        "channel": 6
    }

    for _ in range(20):
        bm.learn(normal_frame)

    # Switch to Monitor Mode
    bm.set_learning_mode(False)

    # 2. Deviation Check
    print("[2] Testing Deviation Check...")

    # Case A: Normal (No deviation)
    dev = bm.check_deviation(normal_frame)
    assert dev is None, "Should be no deviation for normal frame"
    print("   -> Normal frame pass")

    # Case B: Vendor Anomaly (Attack)
    attack_frame = normal_frame.copy()
    attack_frame["vendor_oui"] = "Espressif"

    dev = bm.check_deviation(attack_frame)
    assert dev is not None, "Should detect vendor mismatch"
    assert dev["score"] >= 1.0
    print(f"   -> Detected Vendor Mismatch: {dev['reasons']}")

    # Case C: Signal Spike (Attack)
    spike_frame = normal_frame.copy()
    spike_frame["rssi_dbm"] = -30 # Huge spike from -60

    dev = bm.check_deviation(spike_frame)
    assert dev is not None
    print(f"   -> Detected Signal Anomaly: {dev['reasons']} (Score: {dev['score']})")


    # 3. Risk Scoring (Prob x Impact)
    print("[3] Testing Risk Scoring...")
    scorer = EnhancedRiskScorer(whitelist=["MyCorp", "00:11:22:33:44:55"])

    # Whitelisted but Deviated = High Risk
    # We simulate passing the deviation score from Controller
    result = scorer.calculate_risk(attack_frame, deviation_score=1.0)
    print(f"   -> Risk Score with Deviation (Whitelisted): {result['risk_score']}")

    # Impact 1.0 * (Base + 1.0) * 100 -> Should be 100
    assert result['risk_score'] >= 90

    # Unknown Network (Impact 0.5)
    unknown_frame = {"ssid": "Rando", "bssid": "AA:AA:AA:AA:AA:AA"}
    result_u = scorer.calculate_risk(unknown_frame, deviation_score=1.0)
    print(f"   -> Risk Score with Deviation (Unknown): {result_u['risk_score']}")
    # Impact 0.5 * (Base + 1.0) * 100 -> Should be ~50-60 depending on base
    assert result_u['risk_score'] <= 60


    # 4. Alert Deduplication
    print("[4] Testing Alert Deduplication...")
    am = AlertManager(dedup_window=2) # 2 sec window

    alert1 = {"alert_type": "baseline", "title": "Test", "bssid": "X"}

    assert am.process(alert1) is True
    assert am.process(alert1) is False # Duplicate
    print("   -> Duplicate suppressed detected")

    time.sleep(2.1)
    assert am.process(alert1) is True # Expired
    print("   -> Expiry worked")

    cleanup()
    print("=== Verification SUCCESS ===")

if __name__ == "__main__":
    test_phase2()
