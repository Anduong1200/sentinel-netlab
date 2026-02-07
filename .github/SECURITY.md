# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

---

## Reporting a Vulnerability

### Contact

**Email**: [anduong1200@gmail.com](mailto:anduong1200@gmail.com)

**Subject**: `[SECURITY] Sentinel NetLab - <Brief Description>`

### What to Include

1. **Description** — Clear explanation of the vulnerability
2. **Impact** — Potential security impact (data exposure, privilege escalation, etc.)
3. **Steps to Reproduce** — Detailed reproduction steps
4. **Affected Components** — sensor, controller, API, etc.
5. **Suggested Fix** — If you have one (optional)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 3 business days |
| Initial Assessment | Within 7 days |
| Fix Development | Depends on severity |
| Public Disclosure | Coordinated, after fix |

### Severity Levels

| Severity | Description | Target Fix Time |
|----------|-------------|-----------------|
| Critical | Remote code execution, data breach | 24-48 hours |
| High | Privilege escalation, auth bypass | 7 days |
| Medium | Information disclosure | 14 days |
| Low | Minor issues | Next release |

---

## Responsible Disclosure

We follow **coordinated disclosure**:

1. Reporter sends vulnerability details privately
2. We confirm and assess the issue
3. We develop and test a fix
4. We release the fix and credit the reporter
5. Reporter may publish their findings

**Please do not**:
- Publicly disclose before coordinated fix
- Access data beyond what's necessary for proof
- Perform destructive testing

---

## Security Best Practices

### Deployment

1. **Never expose port 5000 to the internet** — Use SSH tunnel or VPN
2. **Change default secrets** — Generate new values in `.env`
3. **Enable TLS** — All production traffic must be encrypted
4. **Use mTLS** — For sensor-controller authentication
5. **Rate limiting** — Enable at both Nginx and controller

### Credentials

```bash
# Generate secure secrets
openssl rand -hex 32  # CONTROLLER_SECRET_KEY
openssl rand -hex 32  # CONTROLLER_HMAC_SECRET
```

### Sensor Privileges

The sensor requires elevated privileges:
- `root` or
- `CAP_NET_RAW` + `CAP_NET_ADMIN` capabilities

```bash
# Grant capabilities instead of running as root
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### Data Protection

- **PCAPs contain sensitive metadata** — Restrict access
- **MAC addresses are PII** — Use privacy mode (hash MACs)
- **Logs may contain network data** — Secure log storage

---

## Known Security Considerations

### Active Defense Module

The `sensor/attacks.py` module contains offensive capabilities:
- Deauthentication
- Fake AP creation

> ⚠️ **WARNING**: Use only in authorized lab environments.
> Unauthorized use is illegal in most jurisdictions.

### Monitor Mode

Enabling monitor mode captures all wireless traffic in range:
- May include personal devices
- Requires authorization from network owner
- See [Ethics Statement](../docs/ethics_legal/ethics_statement.md) and [LAB_AUTH_TEMPLATE](../LAB_AUTH_TEMPLATE)

---

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| TLS | ✅ | All API traffic encrypted |
| mTLS | ✅ | Mutual authentication |
| HMAC Signing | ✅ | Message tampering protection |
| Replay Protection | ✅ | Sequence number validation |
| Rate Limiting | ✅ | DoS mitigation |
| Secret Scanning | ✅ | CI prevents credential commits |

---

## Security Audits

We welcome security audits. If you've performed an audit:
- Email findings to the security contact
- We'll work with you on the disclosure timeline
- Responsible reporters will be credited

---

*Last Updated: 2026-01-28*
