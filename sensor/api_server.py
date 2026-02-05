#!/usr/bin/env python3
"""
WiFi Scanner API Server - Run in Kali VM
# Integrated version using modular components.
"""

import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Add project root to path for "algos" import
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import modular components
from capture import CaptureEngine, check_monitor_support
from forensics import analyze_pcap

# Import monitoring
from monitoring import (
    ACTIVE_ALERTS,
    LATENCY,
    NETWORKS_FOUND,
    REQUESTS,
    SCAN_DURATION,
    SYSTEM_INFO,
    prometheus_metrics_endpoint,
    setup_json_logging,
)
from parser import WiFiParser
from storage import MemoryStorage, WiFiStorage

from algos.risk import RiskScorer

# Setup JSON logging
setup_json_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow Windows GUI to connect
limiter = Limiter(key_func=get_remote_address, app=app)

# Configuration
# Configuration
from common.security.secrets import require_secret

# Determine environment (Sensor usually runs in prod/dev modes)
env = os.getenv("ENVIRONMENT", "production").lower()

API_KEY = require_secret(
    "Sensor API Key", 
    "WIFI_SCANNER_API_KEY", 
    min_len=32, 
    allow_dev_autogen=True, 
    env=env
)
INTERFACE = os.environ.get("WIFI_SCANNER_INTERFACE", "wlan0")

# Initialize components
capture_engine = CaptureEngine(interface=INTERFACE)
parser = WiFiParser()
storage = WiFiStorage()  # Uses default paths
memory_storage = MemoryStorage()
risk_scorer = RiskScorer()

# Set static info metric
SYSTEM_INFO.labels(version="1.0.0", interface=INTERFACE, engine="tshark").set(1)


@app.route("/")
def index():
    """Root endpoint"""
    return jsonify(
        {
            "message": "Sentinel NetLab Sensor API",
            "version": "1.0.0",
            "docs": "/api/docs",  # Placeholder
        }
    )


@app.before_request
def check_auth():
    """Simple API key authentication"""
    if request.endpoint not in [
        "health",
        "status",
        "metrics",
        "index",
    ]:  # Allow metrics without auth
        api_key = request.headers.get("X-API-Key")
        if api_key != API_KEY:
            # Count failed auth
            REQUESTS.labels(request.path, request.method, "401").inc()
            return jsonify({"error": "Unauthorized"}), 401


@app.after_request
def record_metrics(response):
    """Record request metrics"""
    if request.endpoint != "metrics":
        REQUESTS.labels(request.path, request.method, str(response.status_code)).inc()
    return response


@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint"""
    return prometheus_metrics_endpoint()


@app.route("/health")
def health():
    """Health check endpoint (no auth required)"""
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "interface": INTERFACE,
            "metrics_url": "/metrics",
        }
    )


@app.route("/status")
def status():
    """Get sensor status including interface and capture state"""
    try:
        interface_info = check_monitor_support(INTERFACE)
        capture_status = capture_engine.get_status()

        return jsonify(
            {
                "interface": interface_info,
                "capture": capture_status,
                "storage": {
                    "network_count": storage.get_network_count(),
                    "pcap_stats": storage.get_pcap_stats(),
                },
            }
        )
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/scan")
@limiter.limit("10 per minute")
def scan_networks():
    """Scan for WiFi networks using integrated modules"""
    start_time = time.time()

    # Measure latency for scan specifically
    with LATENCY.labels("/scan").time():
        try:
            # Clear previous scan data
            parser.clear()
            memory_storage.clear()

            # Try real scan first
            networks = perform_real_scan()

        except Exception as e:
            logger.warning(
                f"Real scan failed or not supported: {e}, activating simulation mode"
            )
            networks = get_simulation_data()

        # Calculate risk scores using RiskScorer
        alerts_count = 0
        for net in networks:
            risk_result = risk_scorer.calculate_risk(net)
            net["risk_score"] = risk_result["risk_score"]
            net["risk_level"] = risk_result["risk_level"]
            if net["risk_score"] > 70:
                alerts_count += 1

        # Update metrics
        duration = time.time() - start_time
        SCAN_DURATION.set(duration)
        NETWORKS_FOUND.set(len(networks))
        ACTIVE_ALERTS.set(alerts_count)

        # Store in persistent storage
        try:
            storage.store_networks(networks)
        except Exception as e:
            logger.error(f"Storage error: {e}")

        return jsonify(
            {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "networks": networks,
                "count": len(networks),
                "scan_duration": round(duration, 2),
            }
        )


def perform_real_scan(channels=None, dwell_time=0.5):
    """
    Perform real WiFi scan using CaptureEngine and WiFiParser.
    """
    if channels is None:
        channels = [1, 6, 11]

    networks = []

    def packet_callback(packet):
        """Callback for each captured packet"""
        result = parser.process_packet(packet)
        if result:
            memory_storage.update(result)

    # Enable monitor mode
    if not capture_engine.enable_monitor_mode():
        raise RuntimeError("Failed to enable monitor mode")

    try:
        # Start capture with channel hopping
        capture_engine.start_capture(
            packet_callback=packet_callback,
            channels=channels,
            dwell_time=dwell_time,
            enable_channel_hop=True,
        )

        # Wait for scan to complete (3 passes)
        import time

        total_time = len(channels) * dwell_time * 3
        time.sleep(total_time)

        # Stop capture
        capture_engine.stop_capture()

        # Get parsed networks
        networks = memory_storage.get_all()

    finally:
        # Restore managed mode
        capture_engine.disable_monitor_mode()

    if not networks:
        raise RuntimeError("No networks captured")

    return networks


def get_simulation_data():
    """Generate simulation data for testing or fallback mode"""
    import random

    vendors = ["TP-Link", "Asus", "Netgear", "D-Link", "MikroTik"]
    encryptions = ["Open", "WEP", "WPA2-PSK", "WPA3-SAE"]

    networks = []
    for _i in range(random.randint(3, 8)):  # nosec B311
        vendor = random.choice(vendors)  # nosec B311
        networks.append(
            {
                "ssid": f"{vendor}_{random.randint(100, 999)}",  # nosec B311
                "bssid": f"{random.randint(0xAA, 0xFF):02X}:{random.randint(0xBB, 0xFF):02X}:{random.randint(0xCC, 0xFF):02X}:"  # nosec B311
                f"{random.randint(0x11, 0x99):02X}:{random.randint(0x22, 0x99):02X}:{random.randint(0x33, 0x99):02X}",  # nosec B311
                "signal": random.randint(-90, -40),  # nosec B311
                "channel": random.choice([1, 6, 11]),  # nosec B311
                "encryption": random.choice(encryptions),  # nosec B311
                "vendor": vendor,
            }
        )
    return networks


@app.route("/history")
def get_history():
    """Get scan history from persistent storage"""
    try:
        networks = storage.get_networks(limit=50)
        return jsonify({"networks": networks})
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/export/csv")
def export_csv():
    """Export scan data as CSV"""
    try:
        csv_content = storage.export_csv()
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=wifi_scan.csv"},
        )
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/export/json")
def export_json():
    """Export scan data as JSON"""
    try:
        json_content = storage.export_json()
        return Response(
            json_content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=wifi_scan.json"},
        )
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/forensics/events")
def get_security_events():
    """Get realtime security events (Deauth detections, etc.)"""
    try:
        return jsonify(
            {
                "status": "success",
                "events": parser.security_events[-100:],  # Last 100 events
            }
        )
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/forensics/report/<scan_id>")
def forensics_report(scan_id):
    """
    Generate forensic report for a specific scan.
    Analyzes the PCAP file for attack signatures.
    """
    try:
        # Get PCAP path from storage
        pcap_path = storage.get_pcap_path(scan_id)
        if not pcap_path or not os.path.exists(pcap_path):
            return jsonify({"error": f"PCAP not found for scan_id: {scan_id}"}), 404

        # Get known networks for Evil Twin detection
        known_networks = {}
        for net in parser.networks.values():
            if net.get("ssid"):
                known_networks[net["ssid"]] = {
                    "bssid": net.get("bssid"),
                    "encryption": net.get("encryption"),
                }

        # Run forensic analysis
        report = analyze_pcap(pcap_path, known_networks)
        return jsonify({"status": "success", "scan_id": scan_id, "report": report})

    except Exception as e:
        logger.error(f"Forensics error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("WiFi Scanner API Server (Integrated)")
    print("=" * 50)
    print(f"Interface: {INTERFACE}")
    print(f"API Key: {API_KEY}")
    print("Endpoints:")
    print("  GET /health  - Health check (no auth)")
    print("  GET /status  - Sensor status (no auth)")
    print("  GET /scan    - Scan networks")
    print("  GET /history - Get scan history")
    print("  GET /export/csv  - Export CSV")
    print("  GET /export/json - Export JSON")
    print("  POST /attack/deauth - Deauth attack")
    print("  POST /attack/fakeap - Fake AP attack")
    print("  GET /forensics/events - Security events")
    print("  GET /forensics/report/<id> - Forensic report")
    print("=" * 50)

    host = os.environ.get("SENSOR_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=False)  # nosec B104
