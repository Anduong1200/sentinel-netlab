#!/usr/bin/env python3
"""
doc_cmdlint.py
Checks that commands and files referenced in documentation actually exist.
"""

import os
import re
import sys

# F401: Path unused provided by os
# from pathlib import Path

# Config
DOC_FILES = ["docs/lab/quickstart.md", "docs/prod/deployment.md"]
MAKEFILE = "Makefile"


def get_make_targets(makefile_path):
    targets: set[str] = set()
    if not os.path.exists(makefile_path):
        return targets

    with open(makefile_path, encoding="utf-8") as f:
        for line in f:
            match = re.match(r"^([a-zA-Z0-9_-]+):", line)
            if match:
                targets.add(match.group(1))
    return targets


def check_docs():
    errors = []
    make_targets = get_make_targets(MAKEFILE)

    for doc_path in DOC_FILES:
        if not os.path.exists(doc_path):
            errors.append(f"Missing doc file: {doc_path}")
            continue

        print(f"Checking {doc_path}...")
        with open(doc_path, encoding="utf-8") as f:
            content = f.read()

        # 1. Check Make targets
        # Pattern: `make <target>`
        make_calls = re.findall(r"`make\s+([a-zA-Z0-9_-]+)`", content)
        for target in make_calls:
            if target not in make_targets:
                errors.append(
                    f"[{doc_path}] References non-existent make target: '{target}'"
                )

        # 2. Check Compose files
        # Pattern: `docker compose -f <file>` or `docker-compose -f <file>`
        compose_files = re.findall(
            r"docker-?compose\s+-f\s+([a-zA-Z0-9_./-]+)", content
        )
        for cf in compose_files:
            if not os.path.exists(cf):
                errors.append(
                    f"[{doc_path}] References non-existent compose file: '{cf}'"
                )

    if errors:
        print("\n❌ Documentation Verification Failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\n✅ All documentation references verified.")


if __name__ == "__main__":
    check_docs()
