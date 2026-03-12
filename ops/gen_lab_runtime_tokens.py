#!/usr/bin/env python3
"""
Generate runtime API tokens for Lab stack and persist them to ops/.env.lab.

Why this exists:
- Avoid manual curl + jq + sed workflow.
- Keep dashboard token and real-sensor token in sync with the controller DB.

Prerequisites:
1) Lab stack is running.
2) Bootstrap admin token exists (default: admin-token-dev from ops/init_lab_db.py).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _create_token(base_url: str, admin_token: str, payload: dict[str, str]) -> str:
    url = f"{base_url.rstrip('/')}/api/v1/tokens"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        details = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Token API failed ({e.code}): {details}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot connect to controller: {e.reason}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON response from controller: {raw}") from e

    token = data.get("token")
    if not token:
        raise RuntimeError(f"Token API response missing 'token': {data}")
    return token


def _upsert_env(path: Path, updates: dict[str, str]) -> None:
    if not path.exists():
        raise RuntimeError(f"Env file not found: {path}")

    lines = path.read_text(encoding="utf-8").splitlines()
    updated = set()

    for idx, line in enumerate(lines):
        for key, value in updates.items():
            if line.startswith(f"{key}="):
                lines[idx] = f"{key}={value}"
                updated.add(key)

    for key, value in updates.items():
        if key not in updated:
            lines.append(f"{key}={value}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate lab runtime tokens and write them to .env.lab",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080",
        help="Controller base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--admin-token",
        default="admin-token-dev",
        help="Bootstrap admin token used to call /api/v1/tokens",
    )
    parser.add_argument(
        "--sensor-id",
        default="sensor-real-01",
        help="Sensor ID to bind the generated sensor token",
    )
    parser.add_argument(
        "--dashboard-name",
        default="dashboard-real",
        help="Name label stored for dashboard token",
    )
    parser.add_argument(
        "--sensor-name",
        default="sensor-real",
        help="Name label stored for sensor token",
    )
    parser.add_argument(
        "--env-file",
        default="ops/.env.lab",
        help="Path to env file to update (default: %(default)s)",
    )
    args = parser.parse_args()

    try:
        dashboard_token = _create_token(
            args.base_url,
            args.admin_token,
            {"name": args.dashboard_name, "role": "analyst"},
        )
        sensor_token = _create_token(
            args.base_url,
            args.admin_token,
            {
                "name": args.sensor_name,
                "role": "sensor",
                "sensor_id": args.sensor_id,
            },
        )
        _upsert_env(
            Path(args.env_file),
            {
                "DASHBOARD_API_TOKEN": dashboard_token,
                "SENSOR_AUTH_TOKEN": sensor_token,
            },
        )
    except RuntimeError as e:
        print(f"[gen_lab_runtime_tokens] ERROR: {e}", file=sys.stderr)
        return 1

    print("[gen_lab_runtime_tokens] Tokens generated and env file updated.")
    print(f"[gen_lab_runtime_tokens] Sensor ID bound: {args.sensor_id}")
    print(
        "[gen_lab_runtime_tokens] Next: docker compose --env-file ops/.env.lab "
        "-f ops/docker-compose.lab.yml up -d dashboard"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())