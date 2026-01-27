# Contributing to Sentinel NetLab

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

---

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits of contributions
- Help maintain a welcoming environment for all contributors

---

## How to Contribute

### Reporting Issues

1. **Search existing issues** to avoid duplicates
2. **Use issue templates** when available
3. **Provide details**:
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version, adapter model)
   - Relevant logs

### Submitting Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make changes** following our style guide
4. **Add tests** for new functionality
5. **Run tests** locally:
   ```bash
   cd sensor
   pytest tests/unit/ -v
   ```
6. **Commit** with clear messages:
   ```bash
   git commit -m "feat: add deauth rate limiting"
   ```
7. **Push** and open a pull request

---

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sentinel-netlab.git
cd sentinel-netlab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r sensor/requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest sensor/tests/unit/ -v
```

---

## Code Style

### Python

- Follow **PEP 8** style guide
- Maximum line length: **120 characters**
- Use **type hints** where possible
- Write **docstrings** for public functions

```python
def calculate_risk_score(network: dict, weights: dict) -> float:
    """
    Calculate weighted risk score for a network.
    
    Args:
        network: Network record dictionary
        weights: Weight configuration from risk_weights.yaml
        
    Returns:
        Risk score between 0 and 100
    """
    ...
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `chore`: Maintenance

Examples:
```
feat(parser): add WPA3 IE parsing
fix(buffer): prevent memory leak on flush
docs(readme): update installation instructions
```

---

## Testing

### Writing Tests

- Place unit tests in `sensor/tests/unit/`
- Use pytest fixtures for common setup
- Test edge cases and error conditions

```python
def test_parse_beacon_extracts_ssid(parser):
    """Parser should extract SSID from beacon frame."""
    frame = create_mock_beacon(ssid="TestNetwork")
    result = parser.parse(frame)
    
    assert result.ssid == "TestNetwork"
```

### Running Tests

```bash
# All tests
pytest sensor/tests/ -v

# With coverage
pytest sensor/tests/ --cov=sensor --cov-report=html

# Specific file
pytest sensor/tests/unit/test_parser.py -v
```

---

## Documentation

- Update docs when changing functionality
- Use Markdown for documentation
- Include code examples
- Add mermaid diagrams for complex flows

---

## Pull Request Process

1. Ensure all tests pass
2. Update relevant documentation
3. Add entry to CHANGELOG if significant
4. Request review from maintainers
5. Address feedback promptly
6. Squash commits if requested

---

## Release Process

Releases are managed by maintainers following semantic versioning:

- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

---

## Questions?

- Open a [GitHub Discussion](https://github.com/Anduong1200/sentinel-netlab/discussions)
- Check existing documentation

Thank you for contributing! 🎉
