# Evaluation Metrics

We use standard information retrieval metrics to evaluate detection performance.

## 1. Definitions

- **True Positive (TP)**: Attack frame correctly identified as malicious.
- **False Positive (FP)**: Benign frame incorrectly flagged as malicious.
- **True Negative (TN)**: Benign frame correctly ignored.
- **False Negative (FN)**: Attack frame missed.

## 2. Calculated Metrics

### Precision
Propability that a triggered alert is actually an attack.
$$ Precision = \frac{TP}{TP + FP} $$

### Recall (Detection Rate)
Probability that an attack is detected.
$$ Recall = \frac{TP}{TP + FN} $$

### F1-Score
$$ F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall} $$

### Mean Time to Detection (MTTD)
Time difference between the first attack frame timestamp and the generated alert timestamp.
$$ MTTD = T_{alert} - T_{attack\_start} $$
