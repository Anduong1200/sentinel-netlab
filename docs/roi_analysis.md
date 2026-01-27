# ROI & Business Value Analysis

> Economic justification for deploying Sentinel NetLab by organization scale

---

## 📊 Value Proposition Summary

| Scale | Primary Value | Secondary Value | ROI Potential |
|-------|---------------|-----------------|---------------|
| **Enterprise** | Risk mitigation, Compliance | Automation, Visibility | High |
| **SME** | Cost-effective security | Audit support | Medium-High |
| **Personal/Lab** | Learning, Research | Freelance services | Educational |

---

## 💼 Enterprise / Big Tech

### Use Cases

- Multi-sensor campus monitoring
- SIEM/ELK integration
- Compliance (PCI-DSS, HIPAA wireless requirements)
- Threat hunting and incident response
- Evil Twin / Rogue AP detection at scale

### Value Analysis

| Benefit | Quantification |
|---------|----------------|
| **Risk Reduction** | Prevent 1 major breach/year = $100K-$1M saved |
| **Compliance** | Avoid audit failures = $50K-$500K fines |
| **Automation** | Reduce SOC analyst hours = 40hrs/month @ $75/hr = $36K/year |
| **MTTD Reduction** | Early detection = 20% faster response |

### Cost Breakdown

| Component | One-time | Annual |
|-----------|----------|--------|
| Sensors (10x @ $150) | $1,500 | - |
| Infrastructure (VM, storage) | $2,000 | $5,000 |
| Integration (SIEM, dashboards) | $10,000 | $2,000 |
| Training | $3,000 | $1,000 |
| Ops (0.5 FTE) | - | $40,000 |
| **Total** | **$16,500** | **$48,000** |

### ROI Calculation

```
Assumptions:
- Probability of wireless breach without monitoring: 15%/year
- Cost of breach: $500,000
- Expected loss = 0.15 × $500,000 = $75,000/year

With Sentinel NetLab:
- Probability reduced to: 3%/year
- Expected loss = 0.03 × $500,000 = $15,000/year
- Loss reduction = $60,000/year

ROI = (Benefit - Cost) / Cost
    = ($60,000 - $48,000) / $48,000
    = 25% Year 1

Year 2+: $60,000 / $48,000 = 125% ROI
```

### Break-even

- **Year 1**: After preventing 1 moderate incident
- **Year 2+**: Net positive after ops costs

---

## 🏢 SME (Small-Medium Enterprise)

### Use Cases

- Single-office WiFi monitoring
- Periodic security assessments
- Audit documentation
- Guest WiFi security
- Compliance lite (SOC 2, ISO 27001)

### Value Analysis

| Benefit | Quantification |
|---------|----------------|
| **Risk Reduction** | Prevent 1 breach = $20K-$50K saved |
| **IT Time Savings** | Automated reports = 8hrs/month @ $40/hr = $3,840/year |
| **Audit Support** | Reduce audit prep = 20hrs @ $50/hr = $1,000 |
| **Insurance** | Lower premiums (varies) |

### Cost Breakdown

| Component | One-time | Annual |
|-----------|----------|--------|
| Sensors (3x @ $100) | $300 | - |
| USB Hub + cables | $50 | - |
| VM (existing infra) | $0 | $500 |
| Setup & config | $500 | - |
| Maintenance (0.1 FTE) | - | $6,000 |
| **Total** | **$850** | **$6,500** |

### ROI Calculation

```
Assumptions:
- Probability of wireless incident: 10%/year
- Cost of incident: $25,000
- Expected loss = 0.10 × $25,000 = $2,500/year

With Sentinel NetLab:
- Probability reduced to: 2%/year
- Expected loss = 0.02 × $25,000 = $500/year
- Loss reduction = $2,000/year
- Time savings = $3,840/year
- Total benefit = $5,840/year

ROI = ($5,840 - $6,500) / $6,500 = -10% Year 1
ROI = ($5,840 - $6,500 + $850) / ($850 + $6,500) = -1% Year 1

Year 2+: $5,840 / $6,500 = 90% (near break-even)
```

**Note**: True value often realized when preventing 1 incident

---

## 👤 Personal / Lab / Researcher

### Use Cases

- Learning WiFi security
- CTF competitions
- Academic research
- Freelance pentest prep
- Portfolio building

### Value Analysis

| Benefit | Quantification |
|---------|----------------|
| **Education** | Course equivalent = $500-$2,000 |
| **Research** | Paper/thesis tool = Invaluable |
| **Freelance** | Enable consulting gigs = $500-$5,000/engagement |

### Cost Breakdown

| Component | One-time | Annual |
|-----------|----------|--------|
| USB Adapter (1x) | $30 | - |
| Raspberry Pi (optional) | $50 | - |
| Software | $0 | $0 |
| Time investment | ~40 hours | ~10 hours |
| **Total** | **$30-$80** | **$0** |

### Value Calculation

```
If used for:
- 1 pentest engagement: $1,000 revenue
- Learning value: $1,000 (course equivalent)
- Portfolio value: $500

Total potential value: $2,500
Cost: $80
ROI: 3,000%+
```

---

## 📈 Cost Comparison vs Alternatives

### Enterprise Solutions

| Solution | Annual Cost | Pros | Cons |
|----------|-------------|------|------|
| **Sentinel NetLab** | $50K | Open source, customizable | Requires ops |
| Commercial WIDS (Cisco) | $100K-$500K | Enterprise support | Vendor lock-in |
| Cloud WIDS (Aruba) | $50K-$200K | Easy deploy | Ongoing fees |
| Manual audits only | $20K-$50K | No ongoing cost | Periodic only |

### SME Solutions

| Solution | Annual Cost | Pros | Cons |
|----------|-------------|------|------|
| **Sentinel NetLab** | $6.5K | Low cost | DIY setup |
| External pentest (annual) | $10K-$30K | Professional | Point-in-time |
| Basic commercial | $15K-$40K | Support | Overkill |

---

## 🔢 TCO Calculator

### Inputs

```
Number of sensors: ___
Sensor cost each: $___
Infrastructure: $___/year
FTE percentage: ___%
Average salary: $___/year
Risk probability (without): ___%
Risk probability (with): ___%
Cost per incident: $___
```

### Calculation

```
Hardware = Sensors × Cost
Ops = FTE% × Salary
Annual Cost = Hardware/3 + Infrastructure + Ops

Risk Before = Probability × Incident Cost
Risk After = Reduced Probability × Incident Cost
Benefit = Risk Before - Risk After

ROI Year 1 = (Benefit - Annual Cost - Hardware) / (Annual Cost + Hardware)
ROI Year 2+ = (Benefit - Annual Cost) / Annual Cost
```

---

## 📋 Decision Matrix

### When to Deploy

| Factor | Deploy Now | Consider | Skip |
|--------|------------|----------|------|
| **Budget** | >$5K available | $1-5K | <$1K |
| **Risk Profile** | High-value data | Medium | Low |
| **Compliance** | Required | Nice-to-have | None |
| **IT Capacity** | 0.1+ FTE | Part-time | None |
| **Environment** | Multi-AP, guests | Single AP | Home only |

### Recommendation by Score

| Score | Recommendation |
|-------|----------------|
| 5/5 factors positive | Deploy enterprise version |
| 3-4/5 | Deploy SME version |
| 1-2/5 | Lab/learning use |
| 0/5 | Not needed currently |

---

## 💡 Maximizing Value

### Enterprise

1. Integrate with existing SIEM
2. Automate alerting and response
3. Use for compliance evidence
4. Train SOC on wireless threats

### SME

1. Schedule periodic scans (weekly)
2. Generate automated reports
3. Use for vendor WiFi audits
4. Document for insurance

### Personal

1. Build portfolio projects
2. Create CTF writeups
3. Contribute improvements
4. Offer freelance services

---

## 📊 Sample ROI Report

```
=======================================================================
                    SENTINEL NETLAB ROI ANALYSIS
=======================================================================

Organization: [Company Name]
Date: [Date]
Prepared by: [Name]

-----------------------------------------------------------------------
DEPLOYMENT SUMMARY
-----------------------------------------------------------------------
Scale: SME
Sensors: 3
Coverage: Main office (2 floors)

-----------------------------------------------------------------------
COST ANALYSIS (3-Year)
-----------------------------------------------------------------------
                            Year 1      Year 2      Year 3      Total
Hardware                    $450         $0          $0         $450
Infrastructure              $500        $500        $500       $1,500
Operations (0.1 FTE)       $6,000      $6,000      $6,000     $18,000
-----------------------------------------------------------------------
Total Cost                 $6,950      $6,500      $6,500     $19,950

-----------------------------------------------------------------------
BENEFIT ANALYSIS (3-Year)
-----------------------------------------------------------------------
                            Year 1      Year 2      Year 3      Total
Risk Reduction             $2,000      $2,000      $2,000      $6,000
Time Savings               $3,840      $3,840      $3,840     $11,520
Audit Support              $1,000      $1,000      $1,000      $3,000
-----------------------------------------------------------------------
Total Benefit              $6,840      $6,840      $6,840     $20,520

-----------------------------------------------------------------------
ROI SUMMARY
-----------------------------------------------------------------------
Net Value (3-Year):        $570
Break-even:                Month 36
Cumulative ROI:            3%

Note: Value significantly increases if 1 incident is prevented.
      Single incident of $25,000 would yield 125% ROI.

=======================================================================
```

---

*For custom ROI analysis, contact your security advisor*
