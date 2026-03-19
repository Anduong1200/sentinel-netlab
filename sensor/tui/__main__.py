"""Entry point for: python -m sensor.tui"""

from __future__ import annotations

import sys

_DEPENDENCY_HINTS = {
    "yaml": "PyYAML",
    "textual": "textual",
    "dotenv": "python-dotenv",
}


def format_missing_dependency_message(module_name: str) -> str | None:
    """Return a friendly install hint for common TUI dependency failures."""
    package_name = _DEPENDENCY_HINTS.get(module_name)
    if package_name is None:
        return None

    return (
        f"Missing Python package for TUI startup: {package_name}\n"
        "Install or refresh dependencies with:\n"
        "  pip install -e .\n"
        "If you want the full live-capture stack as well, use:\n"
        "  pip install -e '.[sensor]'"
    )


def main() -> int:
    try:
        from sensor.tui.app import main as run_tui
    except ModuleNotFoundError as exc:
        message = format_missing_dependency_message(exc.name or "")
        if message is None:
            raise
        print(message, file=sys.stderr)
        return 1

    run_tui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
