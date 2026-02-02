#!/usr/bin/env python3
"""
Stability Test Script
Runs sensor scan repeatedly to test long-term stability.

Usage:
    python test_stability.py [--url http://localhost:5000] [--duration 30] [--interval 2]
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any

import requests


def run_scan(
    base_url: str, api_key: str = None, timeout: float = 30.0
) -> dict[str, Any]:
    """
    Run a single scan operation.

    Returns:
        Result dictionary with success status and timing
    """
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    result = {
        "timestamp": datetime.now().isoformat(),
        "success": False,
        "response_time_ms": 0,
        "network_count": 0,
        "error": None,
    }

    try:
        # Check health first
        health_url = f"{base_url.rstrip('/')}/health"
        health_resp = requests.get(health_url, timeout=5)

        if health_resp.status_code != 200:
            result["error"] = f"Health check failed: {health_resp.status_code}"
            return result

        # Get networks
        start = time.perf_counter()
        scan_url = f"{base_url.rstrip('/')}/networks"
        scan_resp = requests.get(scan_url, headers=headers, timeout=timeout)
        end = time.perf_counter()

        result["response_time_ms"] = round((end - start) * 1000, 2)

        if scan_resp.status_code == 200:
            data = scan_resp.json()
            networks = data.get("networks", data.get("results", []))
            result["network_count"] = len(networks)
            result["success"] = True
        else:
            result["error"] = f"Scan failed: {scan_resp.status_code}"

    except requests.exceptions.Timeout:
        result["error"] = "Request timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result


def run_stability_test(
    base_url: str,
    duration_minutes: int = 30,
    interval_minutes: int = 2,
    api_key: str = None,
) -> dict[str, Any]:
    """
    Run stability test for specified duration.

    Returns:
        Test results dictionary
    """
    results = {
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "duration_minutes": duration_minutes,
        "interval_minutes": interval_minutes,
        "base_url": base_url,
        "scans": [],
        "summary": {},
    }

    total_scans = duration_minutes // interval_minutes
    scan_count = 0
    success_count = 0
    crash_count = 0
    response_times = []

    start_time = time.time()
    end_time = start_time + (duration_minutes * 60)

    print("\nStarting stability test...")
    print(f"  Duration: {duration_minutes} minutes")
    print(f"  Interval: {interval_minutes} minutes")
    print(f"  Expected scans: {total_scans}")
    print("-" * 60)

    while time.time() < end_time:
        scan_count += 1
        elapsed = (time.time() - start_time) / 60

        print(f"[{elapsed:.1f}m] Scan #{scan_count}/{total_scans}...", end=" ")

        result = run_scan(base_url, api_key)
        results["scans"].append(result)

        if result["success"]:
            success_count += 1
            response_times.append(result["response_time_ms"])
            print(
                f"✅ {result['network_count']} networks, {result['response_time_ms']:.0f}ms"
            )
        else:
            crash_count += 1
            print(f"❌ {result['error']}")

        # Wait for next interval
        time_left = end_time - time.time()
        if time_left > 0:
            wait_time = min(interval_minutes * 60, time_left)
            time.sleep(wait_time)

    results["end_time"] = datetime.now().isoformat()

    # Calculate summary
    results["summary"] = {
        "total_scans": scan_count,
        "successful_scans": success_count,
        "failed_scans": crash_count,
        "success_rate": (
            round(success_count / scan_count * 100, 2) if scan_count > 0 else 0
        ),
        "avg_response_time_ms": (
            round(sum(response_times) / len(response_times), 2) if response_times else 0
        ),
        "max_response_time_ms": round(max(response_times), 2) if response_times else 0,
        "crash_count": crash_count,
    }

    return results


def generate_report(results: dict[str, Any]) -> str:
    """Generate human-readable stability report."""

    summary = results["summary"]

    # Determine grade
    crash_count = summary["crash_count"]
    if crash_count == 0:
        grade = "PASS (Full Points)"
        score = "5/5"
    elif crash_count == 1:
        grade = "PASS (Partial)"
        score = "3/5"
    else:
        grade = "FAIL"
        score = "0-2/5"

    report = f"""
================================================================================
                    STABILITY TEST REPORT
================================================================================

Generated:  {results["end_time"]}
Target:     {results["base_url"]}
Duration:   {results["duration_minutes"]} minutes
Interval:   {results["interval_minutes"]} minutes

--------------------------------------------------------------------------------
                         SUMMARY
--------------------------------------------------------------------------------

    Total Scans:       {summary["total_scans"]}
    Successful:        {summary["successful_scans"]}
    Failed:            {summary["failed_scans"]}
    Success Rate:      {summary["success_rate"]:.1f}%

    Crash Count:       {summary["crash_count"]}

    Avg Response:      {summary["avg_response_time_ms"]:.0f} ms
    Max Response:      {summary["max_response_time_ms"]:.0f} ms

--------------------------------------------------------------------------------
                         EVALUATION
--------------------------------------------------------------------------------

    Threshold:    0 crashes for full points
                  <=1 crash for partial points

    Crash Count:  {crash_count}

    GRADE: {grade}
    SCORE: {score}

--------------------------------------------------------------------------------
                         SCAN LOG
--------------------------------------------------------------------------------
"""

    for i, scan in enumerate(results["scans"]):
        status = "✅" if scan["success"] else "❌"
        if scan["success"]:
            report += f"    [{i + 1}] {status} {scan['timestamp']} - {scan['network_count']} networks, {scan['response_time_ms']:.0f}ms\n"
        else:
            report += (
                f"    [{i + 1}] {status} {scan['timestamp']} - ERROR: {scan['error']}\n"
            )

    report += """
================================================================================
                    END OF REPORT
================================================================================
"""

    return report


def main():
    parser = argparse.ArgumentParser(description="Stability Test")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL")
    parser.add_argument(
        "-d", "--duration", type=int, default=30, help="Duration in minutes"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=2,
        help="Interval between scans in minutes",
    )
    parser.add_argument("--api-key", help="API key for authentication")
    parser.add_argument(
        "-o", "--output", default="stability_report.txt", help="Output file"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    print("=" * 60)
    print("  Stability Test")
    print("=" * 60)
    print(f"  URL: {args.url}")
    print(f"  Duration: {args.duration} minutes")
    print(f"  Interval: {args.interval} minutes")
    print("=" * 60)

    results = run_stability_test(
        base_url=args.url,
        duration_minutes=args.duration,
        interval_minutes=args.interval,
        api_key=args.api_key,
    )

    if args.json:
        output = json.dumps(results, indent=2)
    else:
        output = generate_report(results)

    # Save report
    with open(args.output, "w") as f:
        f.write(output)

    print(f"\nReport saved to: {args.output}")

    # Final summary
    print("\n" + "=" * 60)
    print("  FINAL RESULTS")
    print("=" * 60)
    summary = results["summary"]
    print(f"  Scans: {summary['successful_scans']}/{summary['total_scans']} successful")
    print(f"  Crashes: {summary['crash_count']}")
    print(f"  Success Rate: {summary['success_rate']:.1f}%")

    if summary["crash_count"] == 0:
        print("\n✅ PASS: No crashes detected")
        sys.exit(0)
    elif summary["crash_count"] == 1:
        print("\n⚠️  PARTIAL: 1 crash detected")
        sys.exit(0)
    else:
        print(f"\n❌ FAIL: {summary['crash_count']} crashes detected")
        sys.exit(1)


if __name__ == "__main__":
    main()
