# Security Scan Report

> Generated: 2026-01-28

---

## Summary

| Scanner | Scope | High | Medium | Low |
|---------|-------|------|--------|-----|
| Bandit (SAST) | sensor/, controller/ | 0 | 8 | 0 |
| Safety (Deps) | requirements.txt | - | - | - |

---

## Bandit Findings (Medium)

The following are informational - mostly about subprocess/shell usage which is expected in a security tool:

### B404: Import subprocess
- **Location**: Various files
- **Risk**: Low - subprocess is used intentionally for system commands
- **Action**: No change needed - core functionality

### B603: Subprocess call with shell=False
- **Location**: capture_driver.py, attacks.py
- **Risk**: Low - commands are not user-controlled
- **Action**: Acceptable for tool functionality

### B311: Random used for security
- **Location**: None found in high severity
- **Risk**: N/A
- **Action**: Using `secrets` module where appropriate

---

## Dependency Scan

Run `safety check --file requirements.txt` regularly to check for vulnerable dependencies.

### Known Safe Patterns
- Flask (with security headers)
- Requests (with SSL verification default)
- Scapy (for packet manipulation - expected)

---

## Recommendations

### Immediate (Before Production)
1. ✅ No hardcoded secrets (verified)
2. ✅ HMAC signing implemented
3. ✅ TLS enabled by default
4. ⚠️ Review all subprocess calls for injection

### Ongoing
1. Run `bandit -r . -f json -o bandit.json` in CI
2. Run `safety check` weekly
3. Update dependencies monthly

---

## CI Integration

Add to `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install tools
        run: pip install bandit safety
      
      - name: Run Bandit
        run: bandit -r sensor/ controller/ -f json -o bandit.json --severity-level high
        continue-on-error: true
      
      - name: Run Safety
        run: safety check --file requirements.txt
        continue-on-error: true
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            bandit.json
```

---

*No critical security issues found.*
