"""
Sentinel NetLab - Sensor Risk Shim
Shim module for backward compatibility with legacy tests expecting 'from risk import RiskScorer'
"""

import os
import sys

# Ensure algos is reachable
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

