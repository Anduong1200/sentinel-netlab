# ML-Based Anomaly Detection

## Model Choice
We use an autoencoder trained on benign wireless telemetry to model
normal behavior.

## Role in the System
- ML does NOT directly trigger alerts
- It provides anomaly scores as inputs to risk scoring

## Rationale
This mitigates false positives caused by:
- Environmental changes
- Concept drift
- Adversarial mimicry

## Limitations
- Requires periodic retraining
- Sensitive to feature selection
