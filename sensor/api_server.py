#!/usr/bin/env python3
"""
WiFi Scanner API Server - Run in Kali VM
# Integrated version using modular components.
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import logging
import os
import time

# Import modular components
from capture import CaptureEngine, check_monitor_support
from parser import WiFiParser
from storage import WiFiStorage, MemoryStorage
from risk import RiskScorer
from attacks import AttackEngine
from forensics import analyze_pcap

# Import monitoring
from monitoring import (
    setup_json_logging, prometheus_metrics_endpoint,
    REQUESTS, LATENCY, SCAN_DURATION, NETWORKS_FOUND, ACTIVE_ALERTS, SYSTEM_INFO
)

# Setup JSON logging
setup_json_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow Windows GUI to connect
limiter = Limiter(key_func=get_remote_address, app=app)

# Configuration
API_KEY = os.environ.get("WIFI_SCANNER_API_KEY")
if not API_KEY:
    logger.warning("WIFI_SCANNER_API_KEY not set! Using default development key.")
    API_KEY = "sentinel-dev-2024"
INTERFACE = os.environ.get("WIFI_SCANNER_INTERFACE", "wlan0")
ALLOW_ACTIVE_ATTACKS = os.environ.get("ALLOW_ACTIVE_ATTACKS", "false").lower() == "true"

# Initialize components
capture_engine = CaptureEngine(interface=INTERFACE)
parser = WiFiParser()
storage = WiFiStorage()  # Uses default paths
memory_storage = MemoryStorage()
risk_scorer = RiskScorer()
attack_engine = AttackEngine(interface=INTERFACE)

# Set static info metric
SYSTEM_INFO.labels(version="1.0.0", interface=INTERFACE, engine="tshark").set(1)

@app.route('/')
def index():
    """Root endpoint"""
    return jsonify({
        "message": "Sentinel NetLab Sensor API",
        "version": "1.0.0",
        "docs": "/api/docs"  # Placeholder
    })

@app.before_request
def check_auth():
    """Simple API key authentication"""
    if request.endpoint not in ['health', 'status', 'metrics', 'index']:  # Allow metrics without auth
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            # Count failed auth
            REQUESTS.labels(request.path, request.method, '401').inc()
            return jsonify({"error": "Unauthorized"}), 401

@app.after_request
def record_metrics(response):
    """Record request metrics"""
    if request.endpoint != 'metrics':
        REQUESTS.labels(
            request.path,
            request.method,
            str(response.status_code)
        ).inc()
    return response

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return prometheus_metrics_endpoint()

@app.route('/health')
def health():
    """Health check endpoint (no auth required)"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "interface": INTERFACE,
        "metrics_url": "/metrics"
    })


@app.route('/status')
def status():
    """Get sensor status including interface and capture state"""
    try:
        interface_info = check_monitor_support(INTERFACE)
        capture_status = capture_engine.get_status()

        return jsonify({
            "interface": interface_info,
            "capture": capture_status,
            "storage": {
                "network_count": storage.get_network_count(),
                "pcap_stats": storage.get_pcap_stats()
            }
        })
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/scan')
@limiter.limit("10 per minute")
def scan_networks():
    """Scan for WiFi networks using integrated modules"""
    start_time = time.time()

    # Measure latency for scan specifically
    with LATENCY.labels('/scan').time():
        try:
            # Clear previous scan data
            parser.clear()
            memory_storage.clear()

            # Try real scan first
            networks = perform_real_scan()

        except Exception as e:
            logger.warning(f"Real scan failed or not supported: {e}, activating simulation mode")
            networks = get_simulation_data()

        # Calculate risk scores using RiskScorer
        alerts_count = 0
        for net in networks:
            risk_result = risk_scorer.calculate_risk(net)
            net['risk_score'] = risk_result['risk_score']
            net['risk_level'] = risk_result['risk_level']
            if net['risk_score'] > 70:
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

        return jsonify({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "networks": networks,
            "count": len(networks),
            "scan_duration": round(duration, 2)
        })


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
            enable_channel_hop=True
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
    for i in range(random.randint(3, 8)):
        vendor = random.choice(vendors)
        networks.append({
            "ssid": f"{vendor}_{random.randint(100, 999)}",
            "bssid": f"{random.randint(0xAA, 0xFF):02X}:{random.randint(0xBB, 0xFF):02X}:{random.randint(0xCC, 0xFF):02X}:"
                     f"{random.randint(0x11, 0x99):02X}:{random.randint(0x22, 0x99):02X}:{random.randint(0x33, 0x99):02X}",
            "signal": random.randint(-90, -40),
            "channel": random.choice([1, 6, 11]),
            "encryption": random.choice(encryptions),
            "vendor": vendor
        })
    return networks


@app.route('/history')
def get_history():
    """Get scan history from persistent storage"""
    try:
        networks = storage.get_networks(limit=50)
        return jsonify({"networks": networks})
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/export/csv')
def export_csv():
    """Export scan data as CSV"""
    try:
        csv_content = storage.export_csv()
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=wifi_scan.csv'}
        )
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/export/json')
def export_json():
    """Export scan data as JSON"""
    try:
        json_content = storage.export_json()
        return Response(
            json_content,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=wifi_scan.json'}
        )
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/attack/deauth', methods=['POST'])
def attack_deauth():
    """
    Perform Deauthentication Attack.
    Requires ALLOW_ACTIVE_ATTACKS=true
    """
    if not ALLOW_ACTIVE_ATTACKS:
        return jsonify({"error": "Active attacks disabled by configuration"}), 403

    try:
        data = request.get_json()
        target_bssid = data.get('bssid')
        client_mac = data.get('client', 'FF:FF:FF:FF:FF:FF')
        count = int(data.get('count', 10))

        if not target_bssid:
            return jsonify({"error": "Missing target_bssid"}), 400

        success = attack_engine.deauth(target_bssid, client_mac, count)
        if success:
            return jsonify({
                "status": "success",
                "message": f"Deauth sent to {target_bssid} ({count} frames)"
            })
        else:
            return jsonify({"error": "Attack failed"}), 500

    except Exception as e:
        logger.error(f"Deauth error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/attack/fakeap', methods=['POST'])
def attack_fakeap():
    """
    Perform Fake AP (Beacon Flood) Attack.
    Requires ALLOW_ACTIVE_ATTACKS=true
    """
    if not ALLOW_ACTIVE_ATTACKS:
        return jsonify({"error": "Active attacks disabled by configuration"}), 403

    try:
        data = request.get_json()
        ssids = data.get('ssids', [])
        count = int(data.get('count', 100))

        if not ssids:
            return jsonify({"error": "Missing ssids list"}), 400

        success = attack_engine.beacon_flood(ssids, count)
        if success:
            return jsonify({
                "status": "success",
                "message": f"Beacon flood sent ({len(ssids)} SSIDs, {count} frames)"
            })
        else:
            return jsonify({"error": "Attack failed"}), 500

    except Exception as e:
        logger.error(f"FakeAP error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/forensics/events')
def get_security_events():
    """Get realtime security events (Deauth detections, etc.)"""
    try:
        return jsonify({
            "status": "success",
            "events": parser.security_events[-100:]  # Last 100 events
        })
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/forensics/report/<scan_id>')
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
                    "encryption": net.get("encryption")
                }

        # Run forensic analysis
        report = analyze_pcap(pcap_path, known_networks)
        return jsonify({
            "status": "success",
            "scan_id": scan_id,
            "report": report
        })

    except Exception as e:
        logger.error(f"Forensics error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
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

    app.run(host='0.0.0.0', port=5000, debug=False)
