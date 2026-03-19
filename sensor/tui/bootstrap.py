"""
Bootstrap helpers for initializing the TUI runtime environment.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ENV_CANDIDATES = (".env", "sensor/.env")


@dataclass
class EnvLoadResult:
    """Outcome of optional .env loading for the TUI."""

    loaded: bool
    path: Path | None
    status: str


def resolve_tui_env_path(
    project_root: Path,
    override: str | None = None,
) -> Path | None:
    """Locate the .env file the TUI should load, if any."""
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override).expanduser())
    else:
        candidates.extend(project_root / name for name in DEFAULT_ENV_CANDIDATES)

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_tui_env(
    project_root: Path,
    override: str | None = None,
) -> EnvLoadResult:
    """Load a repo-local .env file if python-dotenv is available."""
    env_path = resolve_tui_env_path(project_root, override)
    if env_path is None:
        return EnvLoadResult(
            loaded=False,
            path=None,
            status="No .env file detected.",
        )

    try:
        dotenv_module = importlib.import_module("dotenv")
    except ImportError:
        return EnvLoadResult(
            loaded=False,
            path=env_path,
            status="python-dotenv unavailable.",
        )

    load_dotenv = getattr(dotenv_module, "load_dotenv", None)
    if load_dotenv is None:
        return EnvLoadResult(
            loaded=False,
            path=env_path,
            status="python-dotenv unavailable.",
        )

    load_dotenv(env_path, override=False)
    return EnvLoadResult(
        loaded=True,
        path=env_path,
        status=f"Loaded {env_path.name}",
    )
