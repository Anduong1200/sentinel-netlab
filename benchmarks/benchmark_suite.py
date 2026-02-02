#!/usr/bin/env python3
"""
Comprehensive Benchmark Suite for Sentinel NetLab
Measures all key metrics: recall, precision, latency, packet loss, resources, etc.

Usage:
    python benchmark_suite.py --all
    python benchmark_suite.py --recall --latency
"""

import argparse
import csv
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from typing import Any

import psutil
import requests


class BenchmarkSuite:
    """Comprehensive benchmark runner."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "config": config,
            "metrics": {},
        }
        self.base_url = config.get("api_url", "http://localhost:5000")
        self.api_key = config.get("api_key", "")
        self.interface = config.get("interface", "wlan0")

    def _api_request(self, endpoint: str, method: str = "GET", **kwargs) -> dict | None:
        """Make API request."""
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {"X-API-Key": self.api_key} if self.api_key else {}

        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=30, **kwargs)
            else:
                resp = requests.post(url, headers=headers, timeout=30, **kwargs)

            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print(f"  API error: {e}")
        return None

    # =========================================================================
    # 1. Coverage & Detection Metrics
    # =========================================================================

    def measure_detection(self, duration: int = 60) -> dict[str, Any]:
        """
        Measure AP detection count and rate.
        """
        print("\n[1] Measuring Detection Coverage...")

        # Get networks from API
        networks = self._api_request("/networks")
        if not networks:
            return {"error": "Failed to get networks"}

        network_list = networks.get("networks", networks.get("results", []))

        # Count unique APs
        unique_bssids = set()
        unique_ssids = set()
        for net in network_list:
            bssid = net.get("bssid", "").upper()
            ssid = net.get("ssid", "")
            if bssid:
                unique_bssids.add(bssid)
            if ssid and ssid != "<Hidden>":
                unique_ssids.add(ssid)

        result = {
            "ap_count": len(unique_bssids),
            "ssid_count": len(unique_ssids),
            "hidden_networks": len(
                [n for n in network_list if n.get("ssid") in ["", "<Hidden>"]]
            ),
            "encryption_breakdown": {},
        }

        # Encryption breakdown
        for net in network_list:
            enc = net.get("encryption", "Unknown")
            result["encryption_breakdown"][enc] = (
                result["encryption_breakdown"].get(enc, 0) + 1
            )

        self.results["metrics"]["detection"] = result
        print(f"  Found {result['ap_count']} unique APs")
        return result

    def measure_recall_precision(self, gt_file: str, poc_file: str) -> dict[str, Any]:
        """
        Calculate recall and precision against ground truth.
        """
        print("\n[2] Measuring Recall & Precision...")

        if not os.path.exists(gt_file):
            return {"error": f"Ground truth file not found: {gt_file}"}
        if not os.path.exists(poc_file):
            return {"error": f"PoC file not found: {poc_file}"}

        # Parse ground truth (airodump-ng CSV)
        gt_bssids = set()
        with open(gt_file, encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            in_ap = False
            for row in reader:
                if not row:
                    continue
                if "BSSID" in str(row[0]):
                    in_ap = True
                    continue
                if "Station" in str(row[0]):
                    in_ap = False
                if in_ap and len(row) >= 1:
                    bssid = row[0].strip().upper()
                    if len(bssid) == 17 and bssid.count(":") == 5:
                        gt_bssids.add(bssid)

        # Parse PoC JSON
        with open(poc_file) as f:
            data = json.load(f)

        poc_bssids = set()
        networks = data if isinstance(data, list) else data.get("networks", [])
        for net in networks:
            bssid = net.get("bssid", "").strip().upper()
            if bssid:
                poc_bssids.add(bssid)

        # Calculate metrics
        tp = len(gt_bssids & poc_bssids)
        fp = len(poc_bssids - gt_bssids)
        fn = len(gt_bssids - poc_bssids)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0
        )

        result = {
            "ground_truth_count": len(gt_bssids),
            "detected_count": len(poc_bssids),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

        self.results["metrics"]["recall_precision"] = result
        print(f"  Recall: {recall:.2%}, Precision: {precision:.2%}")
        return result

    # =========================================================================
    # 2. Latency & Timing Metrics
    # =========================================================================

    def measure_latency(self, num_requests: int = 50) -> dict[str, Any]:
        """
        Measure API response latency.
        """
        print(f"\n[3] Measuring Latency ({num_requests} requests)...")

        endpoints = ["/health", "/status", "/networks"]
        all_results = {}

        for endpoint in endpoints:
            latencies = []
            for _i in range(num_requests):
                start = time.perf_counter()
                resp = self._api_request(endpoint)
                end = time.perf_counter()

                if resp is not None:
                    latencies.append((end - start) * 1000)

            if latencies:
                sorted_lat = sorted(latencies)
                all_results[endpoint] = {
                    "avg_ms": round(sum(latencies) / len(latencies), 2),
                    "min_ms": round(min(latencies), 2),
                    "max_ms": round(max(latencies), 2),
                    "p50_ms": round(sorted_lat[len(sorted_lat) // 2], 2),
                    "p95_ms": round(sorted_lat[int(len(sorted_lat) * 0.95)], 2),
                    "p99_ms": round(sorted_lat[int(len(sorted_lat) * 0.99)], 2),
                    "success_rate": len(latencies) / num_requests,
                }

        # Overall average
        all_avg = [r["avg_ms"] for r in all_results.values() if "avg_ms" in r]
        overall = {
            "overall_avg_ms": round(sum(all_avg) / len(all_avg), 2) if all_avg else 0,
            "endpoints": all_results,
        }

        self.results["metrics"]["latency"] = overall
        print(f"  Overall avg: {overall['overall_avg_ms']}ms")
        return overall

    def measure_time_to_display(self, iterations: int = 5) -> dict[str, Any]:
        """
        Measure time from capture end to data availability.
        """
        print("\n[4] Measuring Time-to-Display...")

        times = []
        for _i in range(iterations):
            # Start timing
            start = time.perf_counter()

            # Request networks (simulates display)
            resp = self._api_request("/networks")

            end = time.perf_counter()

            if resp:
                times.append(end - start)

        result = {
            "avg_seconds": round(sum(times) / len(times), 3) if times else 0,
            "max_seconds": round(max(times), 3) if times else 0,
            "samples": len(times),
        }

        self.results["metrics"]["time_to_display"] = result
        print(f"  Avg time-to-display: {result['avg_seconds']}s")
        return result

    # =========================================================================
    # 3. Packet Quality Metrics
    # =========================================================================

    def measure_packet_loss(self, gt_pcap: str, poc_pcap: str) -> dict[str, Any]:
        """
        Estimate packet loss by comparing frame counts.
        """
        print("\n[5] Measuring Packet Loss...")

        def count_frames(pcap_file: str) -> int:
            try:
                result = subprocess.run(
                    ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                return len(result.stdout.strip().split("\n"))
            except Exception:
                return 0

        gt_count = count_frames(gt_pcap)
        poc_count = count_frames(poc_pcap)

        if gt_count > 0:
            loss = max(0, (gt_count - poc_count) / gt_count)
        else:
            loss = 0

        result = {
            "ground_truth_frames": gt_count,
            "poc_frames": poc_count,
            "packet_loss_percent": round(loss * 100, 2),
        }

        self.results["metrics"]["packet_loss"] = result
        print(f"  Packet loss: {result['packet_loss_percent']}%")
        return result

    # =========================================================================
    # 4. Resource Metrics
    # =========================================================================

    def measure_resources(self, duration: int = 30) -> dict[str, Any]:
        """
        Measure CPU and RAM usage during operation.
        """
        print(f"\n[6] Measuring Resources ({duration}s)...")

        cpu_samples = []
        mem_samples = []

        start = time.time()
        while time.time() - start < duration:
            cpu_samples.append(psutil.cpu_percent(interval=1))
            mem_samples.append(psutil.virtual_memory().percent)

        # Get process-specific if possible
        process_cpu = 0
        process_mem = 0
        for proc in psutil.process_iter(["name", "cpu_percent", "memory_info"]):
            try:
                if "python" in proc.info["name"].lower():
                    process_cpu = max(process_cpu, proc.info["cpu_percent"])
                    process_mem = max(
                        process_mem, proc.info["memory_info"].rss / 1024 / 1024
                    )
            except Exception as e:
                logging.debug(f"Skipping process access error: {e}")
                continue

        result = {
            "system_cpu_avg_percent": round(sum(cpu_samples) / len(cpu_samples), 2),
            "system_cpu_max_percent": round(max(cpu_samples), 2),
            "system_ram_avg_percent": round(sum(mem_samples) / len(mem_samples), 2),
            "system_ram_max_percent": round(max(mem_samples), 2),
            "python_process_cpu_percent": round(process_cpu, 2),
            "python_process_ram_mb": round(process_mem, 2),
            "samples": len(cpu_samples),
        }

        self.results["metrics"]["resources"] = result
        print(f"  System CPU: {result['system_cpu_avg_percent']}% avg")
        print(f"  System RAM: {result['system_ram_avg_percent']}% avg")
        return result

    def measure_stability(
        self, duration_min: int = 30, interval_min: int = 2
    ) -> dict[str, Any]:
        """
        Measure system stability over time.
        """
        print(f"\n[7] Measuring Stability ({duration_min}min)...")

        total_scans = duration_min // interval_min
        success_count = 0
        crash_count = 0
        time.time()

        for i in range(total_scans):
            try:
                resp = self._api_request("/health")
                if resp and resp.get("status") == "ok":
                    success_count += 1
                else:
                    crash_count += 1
            except Exception:
                crash_count += 1

            if i < total_scans - 1:
                time.sleep(interval_min * 60)

        time.time()
        uptime = success_count / total_scans * 100 if total_scans > 0 else 0

        result = {
            "duration_minutes": duration_min,
            "total_checks": total_scans,
            "successful_checks": success_count,
            "failed_checks": crash_count,
            "uptime_percent": round(uptime, 2),
            "crash_rate": crash_count,
        }

        self.results["metrics"]["stability"] = result
        print(f"  Uptime: {uptime:.1f}%, Crashes: {crash_count}")
        return result

    # =========================================================================
    # 5. Data Quality Metrics
    # =========================================================================

    def measure_rssi_accuracy(self) -> dict[str, Any]:
        """
        Check RSSI values are in reasonable range.
        """
        print("\n[8] Measuring RSSI Accuracy...")

        networks = self._api_request("/networks")
        if not networks:
            return {"error": "Failed to get networks"}

        network_list = networks.get("networks", [])
        rssi_values = [n.get("rssi", 0) for n in network_list if n.get("rssi")]

        valid_rssi = [r for r in rssi_values if -100 <= r <= -10]

        result = {
            "total_readings": len(rssi_values),
            "valid_readings": len(valid_rssi),
            "invalid_readings": len(rssi_values) - len(valid_rssi),
            "validity_rate": (
                round(len(valid_rssi) / len(rssi_values) * 100, 2) if rssi_values else 0
            ),
            "avg_rssi": (
                round(sum(valid_rssi) / len(valid_rssi), 2) if valid_rssi else 0
            ),
            "min_rssi": min(valid_rssi) if valid_rssi else 0,
            "max_rssi": max(valid_rssi) if valid_rssi else 0,
        }

        self.results["metrics"]["rssi_accuracy"] = result
        print(f"  RSSI validity: {result['validity_rate']}%")
        return result

    def measure_encryption_accuracy(self) -> dict[str, Any]:
        """
        Check encryption detection.
        """
        print("\n[9] Measuring Encryption Detection...")

        networks = self._api_request("/networks")
        if not networks:
            return {"error": "Failed to get networks"}

        network_list = networks.get("networks", [])

        valid_encryptions = [
            "Open",
            "WEP",
            "WPA",
            "WPA2",
            "WPA3",
            "WPA2-PSK",
            "WPA2-Enterprise",
        ]

        detected = {}
        unknown = 0
        for net in network_list:
            enc = net.get("encryption", "Unknown")
            if any(v in enc for v in valid_encryptions) or enc in valid_encryptions:
                detected[enc] = detected.get(enc, 0) + 1
            else:
                unknown += 1

        total = len(network_list)
        result = {
            "total_networks": total,
            "identified": total - unknown,
            "unknown": unknown,
            "identification_rate": (
                round((total - unknown) / total * 100, 2) if total > 0 else 0
            ),
            "breakdown": detected,
        }

        self.results["metrics"]["encryption_accuracy"] = result
        print(f"  Encryption identification: {result['identification_rate']}%")
        return result

    # =========================================================================
    # Report Generation
    # =========================================================================

    def generate_report(self) -> str:
        """Generate comprehensive benchmark report."""

        report = f"""
================================================================================
                    SENTINEL NETLAB BENCHMARK REPORT
================================================================================

Generated: {self.results["timestamp"]}
API URL:   {self.base_url}

--------------------------------------------------------------------------------
                         SUMMARY BY CATEGORY
--------------------------------------------------------------------------------

"""
        # Thresholds

        metrics = self.results.get("metrics", {})

        # Detection
        if "recall_precision" in metrics:
            rp = metrics["recall_precision"]
            report += f"""1. COVERAGE & DETECTION
   ----------------------
   Recall:     {rp.get("recall", 0):.2%}  (Big Tech: ≥90%, SME: ≥80%, Lab: ≥70%)
   Precision:  {rp.get("precision", 0):.2%}  (Big Tech: ≥95%, SME: ≥90%, Lab: ≥85%)
   F1 Score:   {rp.get("f1_score", 0):.2%}

   Ground Truth: {rp.get("ground_truth_count", 0)} APs
   Detected:     {rp.get("detected_count", 0)} APs
   True Positives: {rp.get("true_positives", 0)}
   False Positives: {rp.get("false_positives", 0)}
   False Negatives: {rp.get("false_negatives", 0)}

"""

        # Latency
        if "latency" in metrics:
            lat = metrics["latency"]
            report += f"""2. LATENCY & TIMING
   -----------------
   Overall Avg RTT:  {lat.get("overall_avg_ms", 0):.0f} ms  (Big Tech: <500ms, SME: <1s, Lab: <2s)

   By Endpoint:
"""
            for ep, data in lat.get("endpoints", {}).items():
                report += f"     {ep}: avg={data.get('avg_ms', 0):.0f}ms, p95={data.get('p95_ms', 0):.0f}ms\n"
            report += "\n"

        # Packet Loss
        if "packet_loss" in metrics:
            pl = metrics["packet_loss"]
            report += f"""3. PACKET QUALITY
   ---------------
   Packet Loss:  {pl.get("packet_loss_percent", 0):.1f}%  (Big Tech: <5%, SME: <10%, Lab: <15%)
   GT Frames:    {pl.get("ground_truth_frames", 0)}
   PoC Frames:   {pl.get("poc_frames", 0)}

"""

        # Resources
        if "resources" in metrics:
            res = metrics["resources"]
            report += f"""4. RESOURCE USAGE
   ---------------
   CPU (avg):   {res.get("system_cpu_avg_percent", 0):.1f}%  (Big Tech: <50%, SME: <70%, Lab: <80%)
   CPU (max):   {res.get("system_cpu_max_percent", 0):.1f}%
   RAM (avg):   {res.get("system_ram_avg_percent", 0):.1f}%
   RAM (max):   {res.get("system_ram_max_percent", 0):.1f}%

"""

        # Stability
        if "stability" in metrics:
            stab = metrics["stability"]
            report += f"""5. STABILITY
   ---------
   Uptime:      {stab.get("uptime_percent", 0):.1f}%  (Big Tech: 99.9%, SME: 99%, Lab: 95%)
   Crashes:     {stab.get("crash_rate", 0)}
   Test Duration: {stab.get("duration_minutes", 0)} minutes

"""

        # Data Quality
        if "rssi_accuracy" in metrics:
            rssi = metrics["rssi_accuracy"]
            report += f"""6. DATA QUALITY - RSSI
   --------------------
   Validity Rate: {rssi.get("validity_rate", 0):.1f}%
   Avg RSSI:      {rssi.get("avg_rssi", 0)} dBm
   Range:         {rssi.get("min_rssi", 0)} to {rssi.get("max_rssi", 0)} dBm

"""

        if "encryption_accuracy" in metrics:
            enc = metrics["encryption_accuracy"]
            report += f"""7. DATA QUALITY - ENCRYPTION
   --------------------------
   Identification Rate: {enc.get("identification_rate", 0):.1f}%

   Breakdown:
"""
            for k, v in enc.get("breakdown", {}).items():
                report += f"     {k}: {v}\n"
            report += "\n"

        # Grade
        report += """--------------------------------------------------------------------------------
                         OVERALL GRADE
--------------------------------------------------------------------------------

"""
        grade_points = 0
        max_points = 0

        if "recall_precision" in metrics:
            recall = metrics["recall_precision"].get("recall", 0)
            if recall >= 0.9:
                grade_points += 30
            elif recall >= 0.8:
                grade_points += 25
            elif recall >= 0.7:
                grade_points += 20
            max_points += 30

        if "latency" in metrics:
            lat_avg = metrics["latency"].get("overall_avg_ms", 9999)
            if lat_avg < 500:
                grade_points += 20
            elif lat_avg < 1000:
                grade_points += 15
            elif lat_avg < 2000:
                grade_points += 10
            max_points += 20

        if "stability" in metrics:
            uptime = metrics["stability"].get("uptime_percent", 0)
            if uptime >= 99:
                grade_points += 20
            elif uptime >= 95:
                grade_points += 15
            elif uptime >= 90:
                grade_points += 10
            max_points += 20

        if max_points > 0:
            score = grade_points / max_points * 100
            if score >= 90:
                grade = "A - Excellent"
            elif score >= 80:
                grade = "B - Good"
            elif score >= 70:
                grade = "C - Satisfactory"
            elif score >= 60:
                grade = "D - Pass"
            else:
                grade = "F - Needs Improvement"

            report += f"   Score: {grade_points}/{max_points} ({score:.0f}%)\n"
            report += f"   Grade: {grade}\n"

        report += """
================================================================================
                    END OF REPORT
================================================================================
"""

        return report

    def save_results(self, output_dir: str = "benchmark_results"):
        """Save all results to files."""
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON
        json_file = os.path.join(output_dir, f"benchmark_{timestamp}.json")
        with open(json_file, "w") as f:
            json.dump(self.results, f, indent=2)

        # Save report
        report_file = os.path.join(output_dir, f"benchmark_{timestamp}.txt")
        with open(report_file, "w") as f:
            f.write(self.generate_report())

        print(f"\nResults saved to {output_dir}/")
        return json_file, report_file


def main():
    parser = argparse.ArgumentParser(description="Sentinel NetLab Benchmark Suite")

    # Test selection
    parser.add_argument("--all", action="store_true", help="Run all benchmarks")
    parser.add_argument("--detection", action="store_true", help="Run detection test")
    parser.add_argument(
        "--recall", action="store_true", help="Run recall/precision test"
    )
    parser.add_argument("--latency", action="store_true", help="Run latency test")
    parser.add_argument("--resources", action="store_true", help="Run resource test")
    parser.add_argument("--stability", action="store_true", help="Run stability test")
    parser.add_argument("--quality", action="store_true", help="Run data quality tests")

    # Configuration
    parser.add_argument("--url", default="http://localhost:5000", help="API URL")
    parser.add_argument("--api-key", default="", help="API key")
    parser.add_argument("--interface", default="wlan0", help="WiFi interface")
    parser.add_argument("--gt-csv", help="Ground truth CSV (airodump-ng)")
    parser.add_argument("--poc-json", help="PoC JSON output")
    parser.add_argument(
        "--output", default="benchmark_results", help="Output directory"
    )
    parser.add_argument(
        "-n",
        "--requests",
        type=int,
        default=50,
        help="Number of requests for latency test",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=5,
        help="Duration for resource/stability test (minutes)",
    )

    args = parser.parse_args()

    config = {"api_url": args.url, "api_key": args.api_key, "interface": args.interface}

    suite = BenchmarkSuite(config)

    print("=" * 60)
    print("  Sentinel NetLab Benchmark Suite")
    print("=" * 60)

    run_all = args.all or not any(
        [
            args.detection,
            args.recall,
            args.latency,
            args.resources,
            args.stability,
            args.quality,
        ]
    )

    if run_all or args.detection:
        suite.measure_detection()

    if run_all or args.recall:
        if args.gt_csv and args.poc_json:
            suite.measure_recall_precision(args.gt_csv, args.poc_json)
        else:
            print("\n[!] Skipping recall test: --gt-csv and --poc-json required")

    if run_all or args.latency:
        suite.measure_latency(args.requests)
        suite.measure_time_to_display()

    if run_all or args.resources:
        suite.measure_resources(args.duration * 60 if args.duration < 5 else 30)

    if run_all or args.stability:
        suite.measure_stability(args.duration, 1)

    if run_all or args.quality:
        suite.measure_rssi_accuracy()
        suite.measure_encryption_accuracy()

    # Generate and save report
    json_file, report_file = suite.save_results(args.output)

    print("\n" + suite.generate_report())


if __name__ == "__main__":
    main()
