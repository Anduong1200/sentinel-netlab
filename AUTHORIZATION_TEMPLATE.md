# Authorization Template for Active Wireless Testing

> **⚠️ LEGAL REQUIREMENT**: Active wireless testing (deauthentication, fake AP, injection) requires explicit written authorization. Use of these features without authorization may violate computer crime laws.

---

## Authorization Details

| Field | Value |
|-------|-------|
| **Request ID** | AUTH-_____________ |
| **Date** | __________________ |

---

## Requester Information

| Field | Value |
|-------|-------|
| **Name** | ________________________ |
| **Organization** | ________________________ |
| **Role/Title** | ________________________ |
| **Email** | ________________________ |
| **Phone** | ________________________ |

---

## Scope Definition

### Target Environment

| Field | Value |
|-------|-------|
| **Location/Site** | ________________________ |
| **Building/Floor** | ________________________ |
| **BSSID(s)** | ________________________ |
| **SSID(s)** | ________________________ |
| **IP Range (if applicable)** | ________________________ |

### Authorized Actions

- [ ] **Passive Monitoring** - Frame capture only (no injection)
- [ ] **Deauthentication** - Client disconnection testing
- [ ] **Fake AP / Evil Twin** - Rogue access point simulation
- [ ] **Beacon Flooding** - AP spoofing for detection testing
- [ ] **Probe Injection** - Client enumeration testing
- [ ] **Other**: _______________________

### Explicitly NOT Authorized

- [ ] Data exfiltration of client traffic
- [ ] Credential harvesting
- [ ] Attacks on systems outside scope
- [ ] _______________________

---

## Time Window

| Field | Value |
|-------|-------|
| **Start Date/Time (UTC)** | YYYY-MM-DD HH:MM |
| **End Date/Time (UTC)** | YYYY-MM-DD HH:MM |
| **Maximum Duration** | 24 hours per authorization |

> ⚡ Authorization expires automatically after the end time.

---

## Technical Constraints

- [ ] Sensor must use signed authorization file
- [ ] HMAC signature required (validity: 24 hours max)
- [ ] All actions logged with audit trail
- [ ] Emergency stop: operator can terminate immediately

**Sensor ID(s) Authorized**: ________________________

---

## Signatures

### Operator (Tester)

| | |
|--|--|
| **Name** | ________________________ |
| **Signature** | ________________________ |
| **Date** | ________________________ |

### Asset Owner / IT Manager

| | |
|--|--|
| **Name** | ________________________ |
| **Title** | ________________________ |
| **Signature** | ________________________ |
| **Date** | ________________________ |

### Legal/Compliance (if required)

| | |
|--|--|
| **Name** | ________________________ |
| **Title** | ________________________ |
| **Signature** | ________________________ |
| **Date** | ________________________ |

---

## Digital Authorization File

For automated enforcement, generate a signed authorization file:

```bash
# Generate authorization JSON
cat > auth.json << 'EOF'
{
  "auth_id": "AUTH-20260128-001",
  "operator": "operator@example.com",
  "sensor_ids": ["sensor-01"],
  "scope": {
    "bssids": ["AA:BB:CC:*"],
    "ssids": ["TestNetwork"],
    "actions": ["deauth", "beacon"]
  },
  "valid_from": "2026-01-28T10:00:00Z",
  "valid_until": "2026-01-28T22:00:00Z"
}
EOF

# Sign with HMAC (using shared secret)
echo -n $(cat auth.json) | openssl dgst -sha256 -hmac "$AUTH_SECRET" -hex

# Run with authorization
python sensor/main.py --auth-file auth.json --auth-signature <signature>
```

---

## Incident Contact

In case of unintended impact during testing:

| Role | Contact |
|------|---------|
| **Primary** | ____________ / ____________ |
| **Escalation** | ____________ / ____________ |
| **Legal** | ____________ / ____________ |

---

## Acknowledgments

By signing this document, all parties acknowledge:

1. The scope and limitations of authorized testing
2. Legal requirements have been reviewed
3. Appropriate insurance/liability coverage exists (if applicable)
4. Test results will be handled according to data protection policies

---

*Template Version: 1.0 | Last Updated: January 2026*
