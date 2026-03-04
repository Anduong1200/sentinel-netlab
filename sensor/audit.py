#!/usr/bin/env python3
"""
Sentinel NetLab - Security Audit CLI
Perform automated WiFi security assessments with Home/SME profiles.

Usage:
    python audit.py --iface wlan0 --profile home --output report.json
    python audit.py --profile sme --format html --output report.html
"""

import argparse
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sensor.auditor import (
    NetworkInfo,
    ReportGenerator,
    SecurityAuditor,
    scan_mock_networks,
)

logger = logging.getLogger(__name__)


def _classify_security(caps: dict) -> str:
    """Classify AP security from capabilities dict."""
    if caps.get("wpa3"):
        return "WPA3"
    if caps.get("wpa2"):
        return "WPA2"
    if caps.get("privacy"):
        return "WEP"
    return "Open"


def _perform_discovery(iface: str) -> list[NetworkInfo]:
    """Perform brief Wi-Fi discovery scan."""
    try:
        import time

        from sensor.capture_driver import CaptureDriver
        from sensor.frame_parser import FrameParser

        driver = CaptureDriver(iface)
        parser = FrameParser()
        discovery_networks = {}

        end_sys_time = time.time() + 10

        with driver.capture_session() as source:
            for packet in source:
                if time.time() > end_sys_time:
                    break
                frame_data = parser.parse_80211_frame(packet)
                if frame_data and frame_data.frame_type in ["beacon", "probe_response"]:
                    bssid = frame_data.bssid
                    if bssid not in discovery_networks:
                        caps = frame_data.capabilities or {}
                        discovery_networks[bssid] = NetworkInfo(
                            bssid=bssid,
                            ssid=frame_data.ssid,
                            channel=frame_data.channel or 1,
                            rssi_dbm=frame_data.rssi_dbm or -100,
                            security=_classify_security(caps),
                            wps_enabled=caps.get("wps", False),
                            pmf_enabled=caps.get("pmf", False),
                            hidden=(not frame_data.ssid),
                            vendor_oui=bssid[:8] if bssid else None,
                            capabilities=caps,
                        )
        return list(discovery_networks.values())
    except Exception as e:
        logger.error(f"Failed to run real scan: {e}")
        logger.info("Falling back to mock network data for demonstration.")
        return scan_mock_networks()


def _offload_report(
    api_url: str, api_token: str, report_data: dict, output_path: Path
) -> None:
    """Offload report to controller API."""
    try:
        import requests

        print(f"Uploading report data to {api_url}...")
        resp = requests.post(
            f"{api_url}/api/v1/reports/generate",
            json=report_data,
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30,
        )
        if resp.status_code == 200:
            print("Remote report generation successful.")
            if resp.headers.get("Content-Type") == "application/pdf":
                pdf_path = output_path.with_suffix(".pdf")
                with open(pdf_path, "wb") as f:
                    f.write(resp.content)
                print(f"Saved remote PDF to {pdf_path}")
        else:
            print(f"Remote generation failed: {resp.text}")
    except Exception as e:
        print(f"Failed to call API: {e}")


def run_audit(args, return_data: bool = False) -> Any:
    """
    Main audit function.

    Args:
        args: Parsed arguments
        return_data: If True, returns the report dict instead of exit code
    """
    start_time = datetime.now(UTC)

    print("\n" + "=" * 60)
    print("🔍 SENTINEL NETLAB SECURITY AUDIT")
    print("=" * 60)
    print(f"Sensor ID: {args.sensor_id}")
    print(f"Interface: {args.iface}")
    print(f"Profile:   {args.profile}")
    print(f"Format:    {args.format}")
    print(f"Started:   {start_time.isoformat()}")
    print("=" * 60 + "\n")

    auditor = SecurityAuditor(args.sensor_id, profile=args.profile)

    if args.mock:
        logger.info("Using mock network data")
        networks = scan_mock_networks()
    else:
        logger.info(f"Scanning on {args.iface}...")
        networks = _perform_discovery(args.iface)

    logger.info(f"Found {len(networks)} networks")

    for network in networks:
        ssid_display = network.ssid or "[Hidden]"
        logger.info(f"Auditing: {ssid_display} ({network.bssid})")
        auditor.audit_network(network)

    end_time = datetime.now(UTC)
    duration = (end_time - start_time).total_seconds()
    report_data = auditor.generate_report_data(duration)

    output_path = Path(args.output)
    generator = ReportGenerator()
    generator.save_report(report_data, output_path, format=args.format)

    if args.api_url and args.api_token:
        _offload_report(args.api_url, args.api_token, report_data, output_path)

    counts = report_data["summary"]["counts"]
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    print(f"Networks Scanned: {report_data['summary']['networks_scanned']}")
    print(f"Duration:         {duration:.1f} seconds")
    print("\nFindings by Severity:")
    print(f"  CRITICAL: {counts.get('critical', 0)}")
    print(f"  HIGH:     {counts.get('high', 0)}")
    print(f"  MEDIUM:   {counts.get('medium', 0)}")
    print(f"  LOW:      {counts.get('low', 0)}")
    print("=" * 60 + "\n")

    if return_data:
        return report_data

    if counts.get("critical", 0) > 0:
        return 2
    elif counts.get("high", 0) > 0:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mock audit with home profile
  python audit.py --sensor-id test --mock --profile home

  # SME audit with HTML output
  python audit.py --sensor-id pi-01 --profile sme --format html --output report.html

  # Real scan
  python audit.py --sensor-id pi-01 --iface wlan0mon --output audit.json

Profiles:
  home  - Home/SOHO router checks (WPS, encryption, defaults)
  sme   - Small/Medium Enterprise (802.1X, VLAN, RADIUS, compliance)

IMPORTANT: Use only on networks you own or have authorization to assess.
See ETHICS.md for legal guidelines.
        """,
    )

    parser.add_argument("--sensor-id", default="audit-cli", help="Sensor identifier")
    parser.add_argument("--iface", default="wlan0", help="WiFi interface")
    parser.add_argument("--output", default="audit_report.json", help="Output file")
    parser.add_argument(
        "--format", choices=["json", "html"], default="json", help="Output format"
    )
    parser.add_argument(
        "--profile", choices=["home", "sme"], default="home", help="Audit profile"
    )
    parser.add_argument("--mock", action="store_true", help="Use mock data")
    parser.add_argument("--api-url", help="Controller API URL for report generation")
    parser.add_argument("--api-token", help="Controller API Token")

    args = parser.parse_args()

    sys.exit(run_audit(args))


if __name__ == "__main__":
    main()
