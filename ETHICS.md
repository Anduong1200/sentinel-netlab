# Ethics & Legal Guidelines

> [!CAUTION]
> **READ THIS BEFORE USING SENTINEL NETLAB**

---

## ⚠️ Authorized Use Only

Sentinel NetLab is a **wireless network monitoring tool** that captures 802.11 radio traffic. This functionality raises significant legal and ethical considerations.

**You may ONLY use this software on:**
- Networks you own
- Networks where you have **explicit written authorization** to monitor
- Isolated lab environments with no third-party traffic

---

## Legal Framework

### United States
- **Wiretap Act (18 U.S.C. § 2511)**: Prohibits unauthorized interception of communications
- **Computer Fraud and Abuse Act**: Prohibits unauthorized access to computer systems
- **FCC Regulations**: Govern radio frequency usage

### European Union
- **GDPR**: MAC addresses may constitute personal data
- **ePrivacy Directive**: Protects confidentiality of communications
- **National implementations**: Vary by member state

### Other Jurisdictions
Research your local laws. Many countries have similar restrictions on:
- Interception of communications
- Unauthorized network access
- Collection of personal data

---

## Ethical Guidelines

### DO ✅

- Obtain written authorization before monitoring any network
- Use anonymization when publishing research
- Report vulnerabilities responsibly
- Educate users about WiFi security risks
- Document all testing activities

### DON'T ❌

- Capture traffic on networks without permission
- Store personally identifiable information unnecessarily
- Publish MAC addresses or SSIDs that could identify individuals
- Use captured data for commercial purposes without consent
- Perform active attacks (even in testing) without authorization

---

## Research Ethics

### Academic Use

If using Sentinel NetLab for academic research:

1. **IRB Approval**: Obtain Institutional Review Board approval if required
2. **Informed Consent**: Consider consent requirements for human subjects
3. **Data Minimization**: Collect only what's necessary
4. **Anonymization**: Remove identifying information before analysis
5. **Secure Storage**: Protect captured data appropriately
6. **Responsible Disclosure**: Report vulnerabilities to vendors

### Publication Guidelines

When publishing research based on Sentinel NetLab:

- Anonymize all MAC addresses and SSIDs
- Redact GPS coordinates or reduce precision
- Do not include raw packet captures
- Acknowledge ethical considerations in methodology

---

## Authorization Template

Use this template to document authorization:

```
WIRELESS NETWORK MONITORING AUTHORIZATION

Date: ________________

Network Owner: ________________________________

I, _________________________, authorize _________________________ 
to conduct wireless network monitoring activities on the following 
network(s):

Network SSID(s): ________________________________
Physical Location: ________________________________
Date Range: ________________________________

Purpose of Monitoring:
[ ] Security Assessment
[ ] Research
[ ] Training/Education
[ ] Other: ________________

Scope:
[ ] Passive monitoring only (no transmission)
[ ] Active testing included (specify: _______________)

Data Handling:
- Data will be stored: ________________________________
- Data will be retained until: ________________________________
- Data will be destroyed by: ________________________________

Authorized Signature: ________________________________
Print Name: ________________________________
Title: ________________________________
Date: ________________________________

Researcher Signature: ________________________________
Print Name: ________________________________
Date: ________________________________
```

---

## Reporting Security Issues

If you discover vulnerabilities using Sentinel NetLab:

1. **Do not exploit** the vulnerability beyond proof-of-concept
2. **Document** your findings responsibly
3. **Report** to the vendor/network owner before public disclosure
4. **Allow reasonable time** for remediation (typically 90 days)

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure process.

---

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS AND COPYRIGHT HOLDERS ARE NOT RESPONSIBLE FOR ANY MISUSE OF THIS SOFTWARE.

Users are solely responsible for ensuring their use complies with all applicable laws and regulations.

---

## Contact

For ethics-related questions: [security@example.com]
