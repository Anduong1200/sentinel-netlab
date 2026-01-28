# Contributing to Sentinel NetLab

Thank you for your interest in contributing! This guide will help you get started.

---

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
make dev

# Run tests to verify setup
make test
```

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-123
```

---

## Development Workflow

### Code Style

- **Linting**: We use [Ruff](https://github.com/astral-sh/ruff) for linting
- **Formatting**: Use `ruff format` or `black`
- **Type hints**: Add type hints to new code

```bash
# Run linter
make lint

# Auto-fix issues
ruff check --fix .
```

### Testing

```bash
# Run all tests
make test

# Run specific tests
pytest tests/unit/test_risk.py -v

# Run with coverage
make test-cov
```

### Pre-commit Checks

Before committing, run:

```bash
make pre-commit
```

---

## Pull Request Process

### 1. Commit Guidelines

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(detector): add WPS attack detection
fix(parser): handle malformed beacon frames
docs: update quickstart guide
```

### 2. Create Pull Request

1. Push your branch: `git push origin feature/your-feature`
2. Open a PR against `develop` (or `main` for hotfixes)
3. Fill out the PR template
4. Request review from maintainers

### 3. Review Checklist

Before requesting review, ensure:

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Security scan passes (`make bandit`)
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG updated (for features/breaking changes)

---

## What to Contribute

### Good First Issues

Look for issues labeled [`good first issue`](https://github.com/Anduong1200/sentinel-netlab/labels/good%20first%20issue).

### Feature Ideas

- New detection algorithms
- Additional WiFi frame parsers
- Dashboard improvements
- Documentation translations
- Performance optimizations

### Security Contributions

If you find a security vulnerability:

1. **DO NOT** open a public issue
2. Email security concerns to: security@example.com
3. See [SECURITY.md](SECURITY.md) for details

---

## Architecture Overview

```
sentinel-netlab/
├── sensor/           # Sensor code (runs on edge devices)
│   ├── main.py       # Entry point
│   ├── parser.py     # Frame parsing
│   ├── wids_*.py     # Detection engines
│   └── schema.py     # Data models (Pydantic)
├── controller/       # Controller API (central server)
│   └── api_server.py # Flask API
├── tests/            # Test suite
│   ├── unit/
│   └── integration/
├── ops/              # Deployment configs
│   ├── docker-compose.yml
│   └── grafana/
└── docs/             # Documentation
```

---

## Adding a New Detector

1. Create detector class in `sensor/wids_detectors.py`:

```python
from sensor.detector_base import BaseDetector, DetectorAlert

class MyDetector(BaseDetector):
    NAME = "my_detector"
    DESCRIPTION = "Detects XYZ attacks"
    
    def ingest(self, data):
        if self._is_suspicious(data):
            return self.create_alert(...)
        return None
```

2. Register in detector registry
3. Add tests in `tests/unit/test_wids.py`
4. Update documentation

---

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

## Questions?

- Open a [Discussion](https://github.com/Anduong1200/sentinel-netlab/discussions)
- Join our community chat (if available)

Thank you for contributing! 🎉
