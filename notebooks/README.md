# Sentinel NetLab Notebooks

This directory contains Jupyter notebooks for analyzing data and evaluating algorithms.

## Setup

To run these notebooks, ensure you have the project root in your Python path or install the package in editable mode:

```bash
pip install -e .
```

## Algorithm Evaluation

The `algorithm_evaluation.ipynb` notebook is a template for benchmarking the detection algorithms.

To use the new `algos` module in a notebook:

```python
import sys
import os
sys.path.append(os.path.abspath('..'))

from algos.evil_twin import AdvancedEvilTwinDetector
from algos.risk import RiskScorer

# Initialize
risk_engine = RiskScorer()
et_detector = AdvancedEvilTwinDetector()

# ... analysis code ...
```
