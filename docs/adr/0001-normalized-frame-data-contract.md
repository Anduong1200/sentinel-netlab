# ADR 0001 — NormalizedFrame as Canonical Data Contract

**Date**: 2026-01-28  
**Status**: Accepted  
**Authors**: Sentinel Team

---

## Context

The Sentinel NetLab system has a multi-stage pipeline:

```
Capture → Parse → Normalize → Transport → Ingest → Score → Alert
```

Each stage needs to exchange data. Without a standardized format:
- Parsers output inconsistent structures
- Controllers can't validate incoming data
- Testing becomes fragmented
- Schema drift causes silent failures

---

## Decision

We adopt **Pydantic models** as the single source of truth for data contracts:

1. `RawFrame` — Parser output (minimal processing)
2. `NormalizedFrame` — Enriched, validated frame
3. `TelemetryBatch` — Transport container
4. `Alert` — Detection output

All models defined in `common/contracts.py`.

### Why Pydantic?

- **Runtime validation** — Catches errors early
- **Type hints** — IDE support, static analysis
- **JSON Schema generation** — OpenAPI compatibility
- **Serialization** — Built-in JSON/dict conversion
- **Python-native** — No separate schema language

---

## Consequences

### Positive

- Single source of truth for data structures
- Automatic validation at sensor and controller
- JSON Schema can be generated for documentation
- Type safety improves code quality
- Easier testing with model factories

### Negative

- Pydantic adds ~50ms import time (acceptable)
- Model changes require coordinated sensor/controller updates
- Strict validation may reject legacy data

### Migration

For existing sensors:
1. Add version field to TelemetryBatch
2. Controller supports both old and new formats during transition
3. Deprecate old format after 2 release cycles

---

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|--------------|
| JSON Schema only | No runtime validation in Python |
| Protocol Buffers | Adds complexity, not Python-native |
| dataclasses | No built-in validation |
| attrs | Less ecosystem support |

---

## References

- [Pydantic Documentation](https://docs.pydantic.dev/)
- [common/contracts.py](../../common/contracts.py)
- [Data Schema Documentation](../architecture/data_schema.md)
