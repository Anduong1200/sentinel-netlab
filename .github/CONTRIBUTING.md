# Contributing to Sentinel NetLab

Thank you for your interest in contributing to Sentinel NetLab! This project aims to be a robust platform for wireless security research and education.

## Development Environment Setup

We recommend using Docker for a consistent development experience, but you can also run locally for debugging.

### Prerequisites (Local)
- Python 3.10+
- `pip`
- `make` (optional but recommended)

### Quick Start
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Anduong1200/sentinel-netlab.git
    cd sentinel-netlab
    ```

2.  **Install Production & Dev Dependencies**:
    The project uses `pyproject.toml`.
    ```bash
    python -m venv venv
    source venv/bin/activate  # or venv\Scripts\activate
    pip install -e .[dev]     # Uses optional-dependencies if defined, or install manually
    # Or purely:
    pip install . 
    pip install pytest ruff black mypy bandit
    ```

3.  **Run Tests**:
    We use `pytest`. You can run tests via Docker (recommended) or locally:
    ```bash
    # Standard way (Docker):
    make test
    
    # Local way:
    pytest tests/
    ```

## Development Standards

### Code Style
We strictly enforce code style using **Ruff** and **Black**.
- **Linting**: `ruff check sensor/ controller/`
- **Formatting**: `ruff format sensor/ controller/`

Please run `make lint` before submitting a PR.

### Testing
- **Unit Tests**: All new logic must have unit tests (`tests/unit`).
- **Integration Tests**: Critical flows (e.g., pipeline ingestion) should have integration tests (`tests/integration`).
- **Coverage**: We aim for steady improvement in test coverage.

### Type Hints
Use Python type hints. We verify with `mypy`.
```python
def process_data(data: dict[str, Any]) -> bool:
    ...
```

## Pull Request Process

1.  Create a feature branch from `main`: `git checkout -b feature/my-cool-feature`.
2.  Implement your changes.
3.  Add tests.
4.  Run linting and tests locally (`make lint`, `make test`).
5.  Update documentation if applicable (e.g., `README.md` or `docs/`).
6.  Push to your fork and submit a PR to `main`.
7.  Fill out the PR template describing your changes.

## Project Structure

- `sentinel.py`: Unified CLI entry point (`monitor`, `scan` modes).
- `sensor/`: Core sensor logic (Capture, Parsing, Normalization).
- `controller/`: Backend API and Aggregation logic.
- `common/`: Shared utilities (OUI, Config, Privacy).
- `algos/`: Detection algorithms (Risk, Evil Twin).
- `ops/`: Docker and deployment configuration.

## Reporting Issues

Please use the GitHub Issue Tracker.
- **Bugs**: Provide steps to reproduce, logs, and environment details.
- **Features**: Describe the use case and expected benefit.

## Security

If you discover a security vulnerability, please refer to [SECURITY.md](SECURITY.md) instead of opening a public issue.
