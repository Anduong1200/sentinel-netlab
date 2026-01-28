#!/usr/bin/env python3
"""
Sentinel NetLab - Algorithm Benchmark Example
Demonstrates how to import and use the consolidated algos package.
"""

import sys
import time
import logging
from pathlib import Path

# Ensure project root is in path
sys.path.append(str(Path(__file__).parent.parent))

from algos.evil_twin import AdvancedEvilTwinDetector
from algos.dos import DeauthFloodDetector
from algos.risk import RiskScorer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("benchmark")

def run_benchmark():
    logger.info("Initializing detectors...")
    
    # 1. Evil Twin Detector
    et_detector = AdvancedEvilTwinDetector()
    
    # 2. DoS Detector
    dos_detector = DeauthFloodDetector()
    
    # 3. Risk Scorer
    risk_scorer = RiskScorer()
    
    logger.info("Detectors initialized successfully.")
    
    # Simulate some processing
    start_time = time.time()
    
    # Test Scenarios
    logger.info("Running test scenarios...")
    
    # Scenario A: Normal Network
    net_normal = {
        'ssid': 'Corporate_WiFi',
        'bssid': 'AA:BB:CC:11:22:33',
        'security': 'WPA2',
        'rssi_dbm': -55,
        'has_pmf': True,
        'vendor': 'Cisco'
    }
    
    score = risk_scorer.score(net_normal)
    logger.info(f"Normal Network Risk Score: {score}")
    
    # Scenario B: Evil Twin
    net_evil = {
        'ssid': 'Corporate_WiFi',
        'bssid': 'DE:AD:BE:EF:00:01', # Different BSSID
        'security': 'Open',          # Downgrade
        'rssi_dbm': -40,             # Stronger signal
        'has_pmf': False,
        'vendor': 'Unknown'
    }
    
    # Note: Evil Twin detection usually requires state/history ingestion
    # This is just a basic instantiation check for this example
    
    logger.info(f"Benchmark complete in {time.time() - start_time:.4f}s")

if __name__ == "__main__":
    run_benchmark()
