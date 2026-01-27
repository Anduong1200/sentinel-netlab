# Deliverables Checklist

## Phần mềm (Code)

### Sensor (Linux VM)
| File | Status | Mô tả |
|------|--------|-------|
| `sensor/api_server.py` | ✅ Complete | Flask REST API (integrated with modules) |
| `sensor/capture.py` | ✅ Complete | CaptureEngine class |
| `sensor/parser.py` | ✅ Complete | WiFiParser + OUI database |
| `sensor/storage.py` | ✅ Complete | WiFiStorage + MemoryStorage |
| `sensor/risk.py` | ✅ Complete | RiskScorer class |
| `sensor/config.py` | ✅ Complete | Configuration management |
| `sensor/requirements.txt` | ✅ Complete | Dependencies |
| `sensor/wifi-scanner.service` | ✅ Complete | Systemd service |

### Controller (Windows)
| File | Status | Mô tả |
|------|--------|-------|
| `controller/scanner_gui.py` | ✅ Complete | Tkinter GUI |
| `controller/requirements.txt` | ✅ Complete | Dependencies |

### Scripts
| File | Status | Mô tả |
|------|--------|-------|
| `scripts/check_driver.py` | ✅ Complete | Driver diagnostics |
| `scripts/setup_vm.sh` | ✅ Complete | VM auto-setup |
| `scripts/install_service.sh` | ✅ Complete | Service installer |
| `scripts/setup_host.ps1` | ✅ Complete | Windows host helper |
| `scripts/setup_helper.ps1` | ✅ Complete | Additional helper |

### Tests
| File | Status | Mô tả |
|------|--------|-------|
| `tests/test_modules.py` | ✅ Complete | Unit tests |
| `tests/compare_recall.py` | ⬜ Pending | Benchmark script |

---

## Tài liệu (Documentation)

| File | Status | Mô tả |
|------|--------|-------|
| `README.md` | ✅ Complete | Project overview |
| `docs/technical_report.md` | ✅ Complete | Full technical report (~90KB) |
| `docs/install_guide.md` | ✅ Complete | Installation guide |
| `docs/api_reference.md` | ✅ Complete | API documentation |
| `docs/risk_management.md` | ✅ Complete | Risk register + runbook |
| `docs/demo_runbook.md` | ✅ Complete | Demo script |
| `docs/roadmap_8weeks.md` | ✅ Complete | Development roadmap |
| `docs/architecture_analysis.md` | ✅ Complete | Architecture comparison |
| `docs/deliverables_checklist.md` | ✅ Complete | This file |

---

## Artifacts (Test Data)

| File | Status | Mô tả |
|------|--------|-------|
| `artifacts/poc.json` | ⬜ Pending | Sample scan output |
| `artifacts/sample.pcap` | ⬜ Pending | Sample PCAP file |
| `artifacts/gt.csv` | ⬜ Pending | Ground truth from airodump-ng |

---

## Demo Materials

| Item | Status | Mô tả |
|------|--------|-------|
| Demo video (3-5 min) | ⬜ Pending | End-to-end demo |
| Presentation slides | ⬜ Pending | 15-20 slides |
| Pre-recorded fallback | ⬜ Pending | Backup demo |

---

## Summary

- **Code**: 15/15 files complete ✅
- **Docs**: 9/9 files complete ✅  
- **Tests**: 1/2 files complete
- **Artifacts**: 0/3 pending
- **Demo**: 0/3 pending

**Overall Progress: ~85%**
