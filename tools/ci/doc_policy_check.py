#!/usr/bin/env python3
"""
doc_policy_check.py
Enforce security policies in documentation.
"""

import os
import re
import sys

# from pathlib import Path # F401

from typing import Any

# Config
PROHIBITED_PATTERNS: list[dict[str, Any]] = [
    # General Safety
    {
        "pattern": r"change_me_in_prod",
        "msg": "Do not use placeholder secrets that might be copy-pasted.",
    },
    {"pattern": r"admin/sentinel", "msg": "Do not document default credentials."},
    # Network Safety (Prod)
    {
        "pattern": r"5432:",
        "paths": ["docs/prod"],
        "msg": "Do not expose Database port (5432) in production docs.",
    },
    {
        "pattern": r"6379:",
        "paths": ["docs/prod"],
        "msg": "Do not expose Redis port (6379) in production docs.",
    },
]


def check_policies():
    errors = []

    # Walk docs directory
    for root, _, files in os.walk("docs"):
        for file in files:
            if not file.endswith(".md"):
                continue

            path = os.path.join(root, file)
            # Normalize path separators
            path = path.replace("\\", "/")

            with open(path, encoding="utf-8") as f:
                content = f.read()

            for rule in PROHIBITED_PATTERNS:
                # Check path filters
                if "paths" in rule:
                    if not any(p in path for p in rule["paths"]):
                        continue

                if re.search(rule["pattern"], content):
                    errors.append(
                        f"[{path}] Policy Violation: {rule['msg']} (Pattern: '{rule['pattern']}')"
                    )

    if errors:
        print("\n❌ Documentation Policy Check Failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\n✅ Documentation policies passed.")


if __name__ == "__main__":
    check_policies()
