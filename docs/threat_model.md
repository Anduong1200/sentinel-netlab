# Threat Model

> STRIDE analysis and Data Flow Diagram for Sentinel NetLab

---

## 1. System Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED ZONE                                  │
│   [WiFi Environment]  [Internet]  [Attacker]                           │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
        ══════════════════╪══════════════════  TRUST BOUNDARY 1
                          │
┌─────────────────────────▼───────────────────────────────────────────────┐
│                        DMZ / SENSOR ZONE                                │
│  ┌──────────────┐   802.11 Frames   ┌──────────────┐                   │
│  │  WiFi Adapter │─────────────────▶│    Sensor    │                   │
│  │ (Monitor Mode)│                   │   Process    │                   │
│  └──────────────┘                   └──────┬───────┘                   │
│                                            │                            │
│                         mTLS + HMAC + Token│                            │
└────────────────────────────────────────────┼────────────────────────────┘
                                             │
        ═════════════════════════════════════╪═════  TRUST BOUNDARY 2
                                             │
┌────────────────────────────────────────────▼────────────────────────────┐
│                       CONTROLLER ZONE                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │
│  │  API Server  │──▶│   Database   │   │    Redis     │                │
│  │   (Flask)    │   │  (Postgres)  │   │  (Cache)     │                │
│  └──────┬───────┘   └──────────────┘   └──────────────┘                │
│         │                                                               │
│         │ Auth + RBAC                                                   │
└─────────┼───────────────────────────────────────────────────────────────┘
          │
        ══╪══════════════════════════════════════════  TRUST BOUNDARY 3
          │
┌─────────▼───────────────────────────────────────────────────────────────┐
│                       OPERATOR ZONE                                     │
│  ┌──────────────┐   ┌──────────────┐                                   │
│  │   Dashboard  │   │   Analyst    │                                   │
│  │    (Web)     │   │   Console    │                                   │
│  └──────────────┘   └──────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Analysis

### Spoofing
| Threat | Risk | Mitigation |
|--------|------|------------|
| Spoofed sensor sending fake telemetry | HIGH | mTLS client certs, API tokens, HMAC signing |
| Impersonated controller | HIGH | TLS certificate pinning, server verification |
| Replay attacks | MEDIUM | Monotonic sequence numbers, timestamp validation |

### Tampering
| Threat | Risk | Mitigation |
|--------|------|------------|
| Modified telemetry in transit | HIGH | HMAC-SHA256 signature on all payloads |
| Altered alerts | MEDIUM | Signed alert payloads, audit logging |
| Database tampering | MEDIUM | DB access controls, encryption at rest |

### Repudiation
| Threat | Risk | Mitigation |
|--------|------|------------|
| Denied sensor actions | LOW | Audit log with sensor ID, timestamp |
| Untracked config changes | LOW | Config versioning, change audit trail |

### Information Disclosure
| Threat | Risk | Mitigation |
|--------|------|------------|
| PCAP data exposure | HIGH | Encryption at rest, access controls |
| Token leakage | HIGH | Token hashing, env-only secrets, rotation |
| Network traffic sniffing | MEDIUM | TLS 1.3 for all connections |

### Denial of Service
| Threat | Risk | Mitigation |
|--------|------|------------|
| Telemetry flood | MEDIUM | Per-sensor rate limiting, quotas |
| Alert spam | MEDIUM | Alert throttling, dedup |
| Controller overload | MEDIUM | Redis queue, backpressure |

### Elevation of Privilege
| Threat | Risk | Mitigation |
|--------|------|------------|
| Sensor → Admin access | HIGH | RBAC with least privilege |
| Token escalation | MEDIUM | Role-bound tokens, no privilege transfer |
| API abuse | MEDIUM | Input validation, pydantic schemas |

---

## 3. Data Flow Diagram

```
                                   EXTERNAL
                                   ┌─────┐
                                   │ WiFi│
                                   │ APs │
                                   └──┬──┘
                                      │ 802.11 frames
                                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│ SENSOR                                                              │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐                │
│  │  Capture   │───▶│   Parser   │───▶│  Detector  │                │
│  │  Engine    │    │            │    │  Plugins   │                │
│  └────────────┘    └────────────┘    └─────┬──────┘                │
│                                            │                        │
│  ┌────────────┐    ┌────────────┐          │ alerts                │
│  │   Buffer   │◀───│  Telemetry │◀─────────┘                       │
│  │  Manager   │    │  Formatter │                                   │
│  └─────┬──────┘    └────────────┘                                   │
│        │                                                            │
│        │ Batch + HMAC                                               │
└────────┼────────────────────────────────────────────────────────────┘
         │ HTTPS + mTLS
         ▼
┌────────────────────────────────────────────────────────────────────┐
│ CONTROLLER                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐                │
│  │ Auth/RBAC  │───▶│  Ingestion │───▶│  Storage   │                │
│  │ Middleware │    │  Handler   │    │  (DB)      │                │
│  └────────────┘    └────────────┘    └────────────┘                │
│                                                                     │
│  ┌────────────┐    ┌────────────┐                                  │
│  │   Alert    │───▶│ Dashboard  │                                  │
│  │  Processor │    │   API      │                                  │
│  └────────────┘    └────────────┘                                  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Security Controls

| Control | Implementation | Status |
|---------|----------------|--------|
| **Transport Security** | TLS 1.3, mTLS optional | ✅ |
| **Authentication** | Bearer tokens, API keys | ✅ |
| **Message Integrity** | HMAC-SHA256 | ✅ |
| **Replay Protection** | Sequence numbers + timestamp | ✅ |
| **Authorization** | RBAC (4 roles) | ✅ |
| **Rate Limiting** | Per-sensor quotas | ✅ |
| **Input Validation** | Pydantic schemas | ✅ |
| **Secrets Management** | Env vars, no commit | ✅ |
| **Audit Logging** | JSON structured logs | ✅ |
| **Certificate Rotation** | Manual (auto TBD) | ⚠️ |

---

## 5. Residual Risks

| Risk | Likelihood | Impact | Mitigation Plan |
|------|------------|--------|-----------------|
| Compromised sensor key | Low | High | Key rotation, monitoring |
| Zero-day in parser | Low | High | Fuzzing, sandboxing |
| Insider threat | Low | High | Audit logs, least privilege |
| Supply chain attack | Low | High | Dependency scanning, SBOM |

---

*Last Updated: January 28, 2026*
