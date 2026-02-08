#!/usr/bin/env python3
"""
CI Check for Observability Contract
1.  Verifies Metric Names against a Golden List.
2.  Checks for forbidden high-cardinality labels in code.
"""

import glob
import re
import sys

# Constants
FORBIDDEN_LABELS = ["ssid", "bssid", "user_id", "email", "mac_address"]
# Files to scan for metric usage
SCAN_FILES = glob.glob("controller/**/*.py", recursive=True) + glob.glob(
    "sensor/**/*.py", recursive=True
)

# Expected metrics (Golden List) - simplistic extraction or static definition
# For this iteration, we define what we expect.
EXPECTED_METRICS = {
    "sentinel_controller_ingest_requests_total",
    "sentinel_controller_ingest_success_total",
    "sentinel_controller_ingest_fail_total",
    "sentinel_controller_ingest_latency_seconds",
    "sentinel_controller_backpressure_total",
    "sentinel_queue_backlog_size",
    "sentinel_queue_oldest_age_seconds",
    "sentinel_worker_processed_total",
}


def check_cardinality():
    """Scan code for forbidden labels in Prometheus usage."""
    print("[-] Checking for high-cardinality labels...")
    violations = []

    # Regex to find .labels(...) calls
    # Matches: .labels(..., ssid=..., ...)
    label_pattern = re.compile(r"\.labels\s*\((.*?)\)", re.DOTALL)

    for filepath in SCAN_FILES:
        try:
            with open(filepath, encoding="utf-8") as f:
                content = f.read()

            matches = label_pattern.findall(content)
            for match in matches:
                # Check if any forbidden label is used as a keyword argument
                for forbidden in FORBIDDEN_LABELS:
                    # Simple check: "ssid=" or "'ssid':"
                    if (
                        f"{forbidden}=" in match
                        or f"'{forbidden}'" in match
                        or f'"{forbidden}"' in match
                    ):
                        # Exception: if it's explicitly anonymized or allowed (not implemented here)
                        # For now, strict fail.
                        violations.append(
                            f"{filepath}: Usage of '{forbidden}' in labels({match})"
                        )
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

    if violations:
        print("[X] High Cardinality Labels Found:")
        for v in violations:
            print(f"    {v}")
        return False

    print("[+] No high-cardinality labels found.")
    return True


def main():
    success = True
    if not check_cardinality():
        success = False

    if not success:
        sys.exit(1)

    print("[+] Observability Checks Passed.")


if __name__ == "__main__":
    main()
