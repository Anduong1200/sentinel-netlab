"""
PR-04: Model layer unification tests.

Ensures:
1. No mutable defaults anywhere in ORM models (`default={}`, `default=[]`).
2. All Pydantic validation schemas used by the controller API exist and are importable.
3. SQLAlchemy Telemetry model's `data` alias works correctly.
"""

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1. Mutable default anti-regression scanner
# ---------------------------------------------------------------------------

MODEL_FILES = [
    Path("controller/db/models.py"),
    Path("controller/baseline/models.py"),
]

# Pattern: Column(..., default={}) or Column(..., default=[])
_MUTABLE_DEFAULT_RE = re.compile(r"default\s*=\s*(\{\}|\[\])")


class TestNoMutableDefaults:
    """Guard against mutable defaults sneaking back into SQLAlchemy columns."""

    @pytest.mark.parametrize("model_file", MODEL_FILES, ids=lambda p: str(p))
    def test_no_mutable_default_in_models(self, model_file: Path):
        if not model_file.exists():
            pytest.skip(f"{model_file} does not exist")

        source = model_file.read_text(encoding="utf-8")
        matches = _MUTABLE_DEFAULT_RE.findall(source)
        assert not matches, (
            f"{model_file} still has mutable defaults: {matches}. "
            "Use `default=dict` or `default=list` instead."
        )


# ---------------------------------------------------------------------------
# 2. Import smoke — canonical schemas are importable
# ---------------------------------------------------------------------------


class TestSchemaImports:
    """Ensure canonical schema modules are importable without error."""

    def test_import_common_schemas_telemetry(self):
        from common.schemas.telemetry import TelemetryBatch, TelemetryRecord

        assert TelemetryRecord is not None
        assert TelemetryBatch is not None

    def test_import_common_schemas_alerts(self):
        from common.schemas.alerts import AlertCreate

        assert AlertCreate is not None

    def test_import_controller_db_models(self):
        from controller.db.models import Alert, Sensor, Telemetry

        assert Sensor is not None
        assert Telemetry is not None
        assert Alert is not None


# ---------------------------------------------------------------------------
# 3. Telemetry data alias correctness
# ---------------------------------------------------------------------------


class TestTelemetryAlias:
    """Verify the `data` property alias on the Telemetry ORM model."""

    def test_data_reads_raw_data(self):
        from controller.db.models import Telemetry

        t = Telemetry()
        t.raw_data = {"ssid": "test", "bssid": "AA:BB:CC:DD:EE:FF"}
        assert t.data == t.raw_data
        assert t.data["ssid"] == "test"

    def test_data_setter_writes_raw_data(self):
        from controller.db.models import Telemetry

        t = Telemetry()
        t.data = {"new_key": "value"}
        assert t.raw_data == {"new_key": "value"}

    def test_no_shared_state_between_instances(self):
        """Two Telemetry instances must not share the same dict object."""
        from controller.db.models import Telemetry

        a = Telemetry(raw_data={"key": "a"})
        b = Telemetry(raw_data={"key": "b"})
        # Mutate a's data and verify b is unaffected
        a.raw_data["extra"] = True
        assert "extra" not in b.raw_data
