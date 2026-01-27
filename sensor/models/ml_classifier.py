"""
ML Models Module for Sentinel NetLab Risk Scoring.
Provides interface for training and using ML-based classifiers.

Currently a STUB - provides fallback to heuristic scoring.
To enable full ML: pip install scikit-learn joblib
"""

import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

MODEL_PATH = "models/risk_classifier.joblib"


def predict_risk(features: Dict[str, float]) -> Dict:
    """
    Predict risk using ML model if available, else return None.

    Args:
        features: Normalized feature vector from FeatureExtractor

    Returns:
        Dict with 'score' and 'probability' or None if model not available
    """
    try:
        import joblib
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            X = [list(features.values())]
            # Probability of "risky" class
            proba = model.predict_proba(X)[0][1]
            return {
                "score": int(proba * 100),
                "probability": round(proba, 3),
                "model": "LogisticRegression"
            }
    except ImportError:
        logger.debug("scikit-learn not installed, skipping ML prediction")
    except Exception as e:
        logger.warning(f"ML prediction failed: {e}")

    return None


def train_model(labeled_data: List[Dict], save_path: str = MODEL_PATH) -> Dict:
    """
    Train a simple Logistic Regression model from labeled data.

    Args:
        labeled_data: List of {"features": {...}, "label": "HIGH"/"LOW"}
        save_path: Path to save the trained model

    Returns:
        Dict with training metrics
    """
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
        import joblib
        import numpy as np

        # Prepare data
        X = [list(d["features"].values()) for d in labeled_data]
        y = [1 if d["label"] in ["HIGH", "MEDIUM"] else 0 for d in labeled_data]

        # Train
        model = LogisticRegression(max_iter=500)
        model.fit(X, y)

        # Evaluate with cross-validation
        scores = cross_val_score(model, X, y, cv=5, scoring='roc_auc')

        # Save
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump(model, save_path)

        return {
            "status": "success",
            "samples": len(labeled_data),
            "auc_cv": round(np.mean(scores), 3),
            "auc_std": round(np.std(scores), 3),
            "model_path": save_path
        }

    except ImportError:
        return {
            "error": "scikit-learn not installed. Run: pip install scikit-learn joblib"}
    except Exception as e:
        return {"error": str(e)}


# Placeholder for future model
class RiskClassifier:
    """
    Wrapper class for ML-based risk classification.
    Can be swapped into EnhancedRiskScorer for production use.
    """

    def __init__(self, model_path: str = MODEL_PATH):
        self.model = None
        self.model_path = model_path
        self._load()

    def _load(self):
        try:
            import joblib
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded ML model from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}")

    def predict(self, features: Dict[str, float]) -> Optional[Dict]:
        if self.model is None:
            return None
        try:
            X = [list(features.values())]
            proba = self.model.predict_proba(X)[0][1]
            return {"score": int(proba * 100), "confidence": round(proba, 2)}
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return None
