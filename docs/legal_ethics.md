# Legal & Ethics Documentation

> This document outlines the legal requirements, ethical considerations, and consent procedures for using Sentinel NetLab.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for **authorized security assessments only**. Unauthorized interception of wireless communications is illegal in most jurisdictions.

### Applicable Laws

| Region | Law | Penalty |
|--------|-----|---------|
| **USA** | Computer Fraud and Abuse Act (CFAA) | Up to 10 years imprisonment |
| **USA** | Wiretap Act (18 U.S.C. § 2511) | Up to 5 years imprisonment |
| **EU** | GDPR + National Criminal Laws | Fines + imprisonment |
| **Vietnam** | Law on Cybersecurity (2018) | Administrative + criminal penalties |

### What This Tool Does

- **Passive Monitoring**: Captures broadcast WiFi frames (beacons, probes)
- **Active Attacks**: Deauthentication, Fake AP (requires explicit enablement)
- **Data Collection**: SSIDs, BSSIDs, MAC addresses, signal strength

---

## ✅ Authorization Requirements

Before using this tool, you **MUST** have:

1. **Written Authorization** from the network owner
2. **Defined Scope** of assessment
3. **Time Window** for testing
4. **Rules of Engagement** (what is/isn't allowed)

### Authorization Checklist

- [ ] Written permission from network owner/administrator
- [ ] Scope clearly defined (networks, IP ranges, time)
- [ ] Emergency contact information available
- [ ] Data handling procedures agreed upon
- [ ] Rules of engagement documented

---

## 📋 Consent Form Template

```
=============================================================================
                    WIRELESS SECURITY ASSESSMENT
                         CONSENT FORM
=============================================================================

ORGANIZATION:      ___________________________________________________
AUTHORIZED BY:     ___________________________________________________
TITLE:             ___________________________________________________
DATE:              ___________________________________________________

SCOPE OF ASSESSMENT:

    Target Networks (SSIDs):
    _________________________________________________________________
    _________________________________________________________________

    Physical Location(s):
    _________________________________________________________________
    _________________________________________________________________

    Time Period:
    Start: ___________________  End: ___________________

AUTHORIZED ACTIVITIES:

    [  ] Passive monitoring (beacon/probe capture)
    [  ] Channel scanning
    [  ] Hidden network detection
    [  ] Client device enumeration
    [  ] Deauthentication testing
    [  ] Fake AP testing
    [  ] Handshake capture
    [  ] Other: _____________________________________________________

RESTRICTIONS:

    [  ] Do NOT disrupt production networks
    [  ] Do NOT capture traffic content (only metadata)
    [  ] Do NOT attack client devices
    [  ] Other: _____________________________________________________

DATA HANDLING:

    [  ] Data will be encrypted at rest
    [  ] Data will be deleted within ____ days after assessment
    [  ] Report will be shared only with authorized personnel

EMERGENCY CONTACT:
    Name: ___________________________________________________________
    Phone: __________________________________________________________
    Email: __________________________________________________________

SIGNATURES:

Network Owner/Authorized Representative:

    Signature: ________________________  Date: ___________________
    Print Name: _______________________

Assessor:

    Signature: ________________________  Date: ___________________
    Print Name: _______________________
    Organization: _____________________

=============================================================================
```

---

## 🔒 Data Handling Procedures

### What Data is Collected

| Data Type | Example | Sensitivity |
|-----------|---------|-------------|
| SSID | "CompanyWiFi" | Low |
| BSSID | AA:BB:CC:DD:EE:FF | Low |
| Client MAC | 11:22:33:44:55:66 | Medium |
| Probe Requests | Device searching for "Home_WiFi" | Medium-High |
| Handshakes | EAPOL frames | High |
| Traffic Content | (Not captured by default) | Critical |

### Data Retention

| Phase | Retention | Action |
|-------|-----------|--------|
| During Assessment | As needed | Secure storage |
| After Assessment | 30 days max | Review + analysis |
| Report Delivered | 7 days | Delete raw data |
| Long-term | 0 days | Complete deletion required |

### Secure Deletion

```bash
# Linux: Secure delete PCAP files
shred -vfz -n 5 *.pcap

# SQLite database
shred -vfz -n 5 wifi_scanner.db

# Verify deletion
ls -la *.pcap *.db  # Should show no files
```

---

## 🎯 Ethical Guidelines

### DO:

- ✅ Get written authorization before any testing
- ✅ Clearly define scope and boundaries
- ✅ Report vulnerabilities responsibly
- ✅ Minimize data collection to what's necessary
- ✅ Encrypt all captured data
- ✅ Delete data after assessment is complete
- ✅ Document all activities

### DON'T:

- ❌ Test networks without authorization
- ❌ Capture more data than needed
- ❌ Share findings with unauthorized parties
- ❌ Leave backdoors or persistent access
- ❌ Disrupt production services unnecessarily
- ❌ Attack client devices without consent

---

## 🛡️ Mock Mode (Default)

For demonstration and testing purposes, enable **Mock Mode**:

```bash
# Environment variable
export MOCK_MODE=true

# Or in config
echo '{"mock_mode": true}' > config.json
```

In Mock Mode:
- No actual packets are captured
- Sample data is used for demonstration
- No wireless interface required
- Safe for presentations

---

## 📝 Incident Response

If you accidentally capture unauthorized data:

1. **Stop** all capture activities immediately
2. **Document** what was captured and when
3. **Notify** the network owner if applicable
4. **Delete** all unauthorized data securely
5. **Report** the incident to your supervisor
6. **Review** procedures to prevent recurrence

---

## 📚 References

### Legal Resources

- [CFAA - Computer Fraud and Abuse Act](https://www.law.cornell.edu/uscode/text/18/1030)
- [Wiretap Act](https://www.law.cornell.edu/uscode/text/18/2511)
- [GDPR Article 5](https://gdpr-info.eu/art-5-gdpr/)
- [Vietnam Cybersecurity Law](https://thuvienphapluat.vn/van-ban/Cong-nghe-thong-tin/Luat-an-ninh-mang-2018-351416.aspx)

### Ethical Guidelines

- [EC-Council Code of Ethics](https://www.eccouncil.org/code-of-ethics/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## ✍️ Acknowledgment

By using Sentinel NetLab, you acknowledge that:

1. You have read and understood this legal/ethics documentation
2. You will only use this tool for authorized assessments
3. You take full responsibility for your actions
4. You will comply with all applicable laws and regulations

---

*Last updated: January 2024*
