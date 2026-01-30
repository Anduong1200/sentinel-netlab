#!/usr/bin/env python3
"""
API Latency Test Script
Measures response time of sensor API endpoints.

Usage:
    python test_latency.py [--url http://localhost:5000] [--requests 50]
"""

import argparse
import json
import statistics
import time
from datetime import datetime
from typing import Any

import requests


def measure_latency(
    url: str, endpoint: str, headers: dict = None, timeout: float = 10.0
) -> float:
    """
    Measure latency for a single request.

    Returns:
        Response time in seconds, or -1 if failed
    """
    full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"

    try:
        start = time.perf_counter()
        response = requests.get(full_url, headers=headers, timeout=timeout)
        end = time.perf_counter()

        if response.status_code == 200:
            return end - start
        else:
            return -1
    except Exception:
        return -1


def run_latency_test(
    base_url: str,
    num_requests: int = 50,
    api_key: str = None,
    endpoints: list[str] = None,
) -> dict[str, Any]:
    """
    Run latency test on multiple endpoints.

    Returns:
        Test results dictionary
    """
    if endpoints is None:
        endpoints = ["/health", "/status", "/networks"]

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    results = {
        "timestamp": datetime.now().isoformat(),
        "base_url": base_url,
        "num_requests": num_requests,
        "endpoints": {},
    }

    for endpoint in endpoints:
        print(f"\nTesting {endpoint}...")
        latencies = []
        errors = 0

        for i in range(num_requests):
            latency = measure_latency(base_url, endpoint, headers)
            if latency >= 0:
                latencies.append(latency)
            else:
                errors += 1

            # Progress indicator
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{num_requests}")

        if latencies:
            latencies_ms = [l * 1000 for l in latencies]
            sorted_latencies = sorted(latencies_ms)

            endpoint_result = {
                "successful_requests": len(latencies),
                "failed_requests": errors,
                "avg_ms": round(statistics.mean(latencies_ms), 2),
                "min_ms": round(min(latencies_ms), 2),
                "max_ms": round(max(latencies_ms), 2),
                "median_ms": round(statistics.median(latencies_ms), 2),
                "p95_ms": round(sorted_latencies[int(len(sorted_latencies) * 0.95)], 2),
                "p99_ms": round(sorted_latencies[int(len(sorted_latencies) * 0.99)], 2),
                "stdev_ms": (
                    round(statistics.stdev(latencies_ms), 2)
                    if len(latencies_ms) > 1
                    else 0
                ),
            }
        else:
            endpoint_result = {
                "successful_requests": 0,
                "failed_requests": errors,
                "error": "All requests failed",
            }

        results["endpoints"][endpoint] = endpoint_result

    return results


def generate_report(results: dict[str, Any]) -> str:
    """Generate human-readable latency report."""

    report = f"""
================================================================================
                    API LATENCY TEST REPORT
================================================================================

Generated: {results["timestamp"]}
Target:    {results["base_url"]}
Requests:  {results["num_requests"]} per endpoint

--------------------------------------------------------------------------------
                         RESULTS BY ENDPOINT
--------------------------------------------------------------------------------
"""

    all_avg = []
    all_p95 = []

    for endpoint, data in results["endpoints"].items():
        report += f"\n  {endpoint}\n"
        report += f"  {'-' * 40}\n"

        if "error" in data:
            report += f"    ERROR: {data['error']}\n"
        else:
            report += f"    Successful:  {data['successful_requests']}\n"
            report += f"    Failed:      {data['failed_requests']}\n"
            report += f"    Average:     {data['avg_ms']:.2f} ms\n"
            report += f"    Median:      {data['median_ms']:.2f} ms\n"
            report += f"    Min:         {data['min_ms']:.2f} ms\n"
            report += f"    Max:         {data['max_ms']:.2f} ms\n"
            report += f"    P95:         {data['p95_ms']:.2f} ms\n"
            report += f"    P99:         {data['p99_ms']:.2f} ms\n"

            all_avg.append(data["avg_ms"])
            all_p95.append(data["p95_ms"])

    report += """
--------------------------------------------------------------------------------
                         OVERALL SUMMARY
--------------------------------------------------------------------------------
"""

    if all_avg:
        overall_avg = statistics.mean(all_avg)
        overall_p95 = max(all_p95)

        # Determine grade
        if overall_avg < 1000:  # < 1s
            avg_grade = "PASS (Full Points)"
            avg_score = "4/4"
        elif overall_avg < 2000:  # < 2s
            avg_grade = "PASS (Partial)"
            avg_score = "2/4"
        else:
            avg_grade = "FAIL"
            avg_score = "0/4"

        if overall_p95 < 2000:  # < 2s
            p95_status = "✅ Within threshold"
        else:
            p95_status = "⚠️ Exceeds threshold"

        report += f"""
    Overall Average:  {overall_avg:.2f} ms
    Overall P95:      {overall_p95:.2f} ms

    Threshold:        avg < 1000ms, p95 < 2000ms

    Average Grade:    {avg_grade}
    Average Score:    {avg_score}
    P95 Status:       {p95_status}
"""
    else:
        report += "    ERROR: No successful requests\n"

    report += """
================================================================================
                    END OF REPORT
================================================================================
"""

    return report


def main():
    parser = argparse.ArgumentParser(description="API Latency Test")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL")
    parser.add_argument(
        "-n", "--requests", type=int, default=50, help="Number of requests"
    )
    parser.add_argument("--api-key", help="API key for authentication")
    parser.add_argument(
        "-o", "--output", default="latency_report.txt", help="Output file"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--endpoints",
        nargs="+",
        default=["/health", "/status", "/networks"],
        help="Endpoints to test",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  API Latency Test")
    print("=" * 60)
    print(f"  URL: {args.url}")
    print(f"  Requests: {args.requests}")
    print(f"  Endpoints: {', '.join(args.endpoints)}")
    print("=" * 60)

    results = run_latency_test(
        base_url=args.url,
        num_requests=args.requests,
        api_key=args.api_key,
        endpoints=args.endpoints,
    )

    if args.json:
        output = json.dumps(results, indent=2)
    else:
        output = generate_report(results)

    # Save report
    with open(args.output, "w") as f:
        f.write(output)

    print(f"\nReport saved to: {args.output}")

    # Quick summary
    print("\n" + "=" * 60)
    print("  QUICK SUMMARY")
    print("=" * 60)

    for endpoint, data in results["endpoints"].items():
        if "avg_ms" in data:
            status = "✅" if data["avg_ms"] < 1000 else "⚠️"
            print(
                f"  {status} {endpoint}: avg={data['avg_ms']:.0f}ms, p95={data['p95_ms']:.0f}ms"
            )
        else:
            print(f"  ❌ {endpoint}: FAILED")


if __name__ == "__main__":
    main()
