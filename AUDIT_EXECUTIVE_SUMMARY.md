# 📋 Executive Summary & Refactoring Roadmap

**Project**: Sentinel NetLab
**Audit Date**: 2026-01-28
**Status**: Beta / Research Prototype

## Executive Brief
Sentinel NetLab is a functional Wireless Intrusion Detection System (WIDS) with strong core logic for frame parsing, risk scoring, and rudimentary anomaly detection. However, it suffers from **structural fragmentation** (split risk engines, isolated wardriving tool) and **documentation mismatches** that hinder production adoption. The codebase is "Research Grade" – correctly implementing algorithms but lacking "Production Grade" resilience, standardized interfaces, and unified logic.

**Key Findings**:
1.  **Identity Crisis**: The tool is split between a "Wardriving Utility" and a "Continuous WIDS". These need to be unified.
2.  **Logic duplication**: Two Risk Engines exist (`algos/` vs `common/`).
3.  **Documentation Gap**: Docs promise features (or files) that are missing or refactored.
4.  **Security**: "Active Defense" features exist but lack rigorous safety interlocks for a publicly available tool.

---

## 📅 8-Week Refactoring Roadmap

### Week 1: Scope & Threat Model (Foundational)
- **Goal**: Define boundaries and success metrics.
- **Tasks**:
    - [ ] Create `THREAT_MODEL.md` (IEEE format: Threat Taxonomy).
    - [ ] Define Metrics: Precision/Recall goals, Max False Positive Rate.
    - [ ] Decide: Is this a WIDS (Monitor) or Audit Tool (Walk)? -> **Decision: It is a Platform with two modes.**
    - [ ] cleanup: Remove `sensor/risk.py` references; appoint `common/risk_engine.py` as Core.

### Week 2: Lab & Data (Validation)
- **Goal**: rigorous testing environment.
- **Tasks**:
    - [ ] Setup `tests/lab/` with PCAP replays of attacks (Deauth, Evil Twin).
    - [ ] Create "Golden Dataset" for regression testing.
    - [ ] Fix `Wardrive` output format to match `Controller` ingest schema.

### Week 3-4: Build Core Features (Refactoring)
- **Goal**: Unified Sensor Logic.
- **Tasks**:
    - [ ] **Data Pipeline**: Refactor `SensorController` to support a "One-Shot" mode (Wardriving) and "Daemon" mode (WIDS) using the same pipeline.
    - [ ] **Risk Engine**: Merge `algos/risk.py` features into `common/risk_engine.py`.
    - [ ] **Policy**: Implement `policy.yaml` to configure "Active Defense" enabled/disabled state legally.

### Week 5-6: Testing & Optimization
- **Goal**: Production Hardening.
- **Tasks**:
    - [ ] **Integration Tests**: `pytest` running Sensor + Controller (Docker) + Mock Driver.
    - [ ] **Tuning**: Adjust Risk Weights based on Week 2 interactions.
    - [ ] **Hardening**: Add mTLS support for Sensor<->Controller.

### Week 7: Deployment & Documentation
- **Goal**: Ease of Use.
- **Tasks**:
    - [ ] **Docs**: Rewrite `README.md` to reflect "Platform" status.
    - [ ] **Deploy**: Create simple `install.sh` for Raspberry Pi (Systemd + Docker).
    - [ ] **IEEE Paper**: Draft standard technical report from `docs/research/`.

### Week 8: Final Release
- **Goal**: v1.0.0 Launch.
- **Tasks**:
    - [ ] Demo Video / Walkthrough.
    - [ ] Final Security Scan (Bandit/Safety).
    - [ ] Release Tags & PyPI/DockerHub push.

---

## Code Cleanup Checklist (Immediate)
- [ ] Delete `sensor/risk.py` refs (Update to `common/risk_engine.py`).
- [ ] Move `wardrive.py` to `sensor/modes/` to signify it's part of the package, not a loose script.
- [ ] Add `MANIFEST.in` to include non-code assets (Config, Schemas) in build.
- [ ] Add `__init__.py` to all test subfolders.
