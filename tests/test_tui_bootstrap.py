import sys
import types
from pathlib import Path

from sensor.tui.bootstrap import load_tui_env, resolve_tui_env_path


def test_resolve_tui_env_path_prefers_project_dotenv(tmp_path: Path):
    (tmp_path / ".env").write_text("SENSOR_ID=env-root\n")
    sensor_dir = tmp_path / "sensor"
    sensor_dir.mkdir()
    (sensor_dir / ".env").write_text("SENSOR_ID=env-sensor\n")

    resolved = resolve_tui_env_path(tmp_path)

    assert resolved == tmp_path / ".env"


def test_resolve_tui_env_path_uses_override(tmp_path: Path):
    override = tmp_path / "custom.env"
    override.write_text("SENSOR_ID=custom\n")

    resolved = resolve_tui_env_path(tmp_path, str(override))

    assert resolved == override


def test_load_tui_env_invokes_python_dotenv(monkeypatch, tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("SENSOR_ID=env-root\n")
    calls = []

    fake_dotenv = types.SimpleNamespace(
        load_dotenv=lambda path, override=False: calls.append((Path(path), override))
    )
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    result = load_tui_env(tmp_path)

    assert result.loaded is True
    assert result.path == env_path
    assert calls == [(env_path, False)]


def test_load_tui_env_handles_missing_dependency(monkeypatch, tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("SENSOR_ID=env-root\n")
    monkeypatch.delitem(sys.modules, "dotenv", raising=False)

    import importlib

    original_import_module = importlib.import_module

    def fake_import_module(name: str):
        if name == "dotenv":
            raise ImportError("missing")
        return original_import_module(name)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    result = load_tui_env(tmp_path)

    assert result.loaded is False
    assert result.path == env_path
    assert result.status == "python-dotenv unavailable."


def test_load_tui_env_handles_missing_file(tmp_path: Path):
    result = load_tui_env(tmp_path)

    assert result.loaded is False
    assert result.path is None
    assert result.status == "No .env file detected."
