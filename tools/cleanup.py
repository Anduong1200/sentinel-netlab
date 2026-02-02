#!/usr/bin/env python3
"""
Repository Cleanup Script
Removes artifacts, caches, and temporary files to maintain repository hygiene.
"""

from pathlib import Path
import shutil

# Patterns to clean
CLEANUP_PATTERNS = [
    "**/__pycache__",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.pyd",
    "**/.pytest_cache",
    "**/.ruff_cache",
    "**/.mypy_cache",
    "**/.coverage",
    "**/.tox",
    "**/.venv",
    "**/*.egg-info",
    "**/*.log",
    "**/bandit_output*.txt",
    "**/integration_output*.txt",
    "**/unit_test_output*.txt",
    "**/bluetooth_log.json",
    "**/file_list.txt",
    "**/.dos_state.json",
    "**/test_sentinel.db",
    "**/.env",
    "**/.DS_Store",
]

# Root directory (assumes script is in tools/)
ROOT_DIR = Path(__file__).parent.parent.resolve()

def cleanup():
    print(f"Cleaning repository at: {ROOT_DIR}")
    removed_count = 0

    for pattern in CLEANUP_PATTERNS:
        # Recursive search
        for path in ROOT_DIR.glob(pattern):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                    print(f"Removed directory: {path.relative_to(ROOT_DIR)}")
                else:
                    path.unlink()
                    print(f"Removed file: {path.relative_to(ROOT_DIR)}")
                removed_count += 1
            except Exception as e:
                print(f"Error removing {path}: {e}")

    print(f"Cleanup complete. Removed {removed_count} items.")

if __name__ == "__main__":
    cleanup()
