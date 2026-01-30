import sys
import os

# Ensure cwd is in path (simulating running from root)
sys.path.insert(0, os.getcwd())

try:
    from algos.risk import RiskScorer
    from ml.anomaly_model import SimpleAutoencoder

    print("SUCCESS: Imports working")

    scorer = RiskScorer()
    print("SUCCESS: RiskScorer instantiated")

    model = SimpleAutoencoder(input_dim=10)
    print("SUCCESS: ML Model instantiated")

except ImportError as e:
    print(f"FAILURE: ImportError: {e}")
except Exception as e:
    print(f"FAILURE: Error: {e}")
