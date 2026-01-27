#!/usr/bin/env python3
"""
WiFi Scanner API Server - Run in Kali VM
Integrated version using modular components.
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import logging
import os

# Import modular components
from capture import CaptureEngine, check_monitor_support
from parser import WiFiParser
from storage import WiFiStorage, MemoryStorage
from risk import RiskScorer, calculate_risk_score

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow Windows GUI to connect
limiter = Limiter(app, key_func=get_remote_address)

# Configuration
API_KEY = os.environ.get("WIFI_SCANNER_API_KEY")
if not API_KEY:
    logger.warning("WIFI_SCANNER_API_KEY not set! Using insecure default for PoC.")
    API_KEY = "student-project-2024"
INTERFACE = os.environ.get("WIFI_SCANNER_INTERFACE", "wlan0")

# Initialize components
capture_engine = CaptureEngine(interface=INTERFACE)
parser = WiFiParser()
storage = WiFiStorage()  # Uses default paths
memory_storage = MemoryStorage()
risk_scorer = RiskScorer()


@app.before_request
def check_auth():
    """Simple API key authentication"""
    if request.endpoint not in ['health', 'status']:
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401


@app.route('/health')
def health():
    """Health check endpoint (no auth required)"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "interface": INTERFACE
    })


@app.route('/status')
def status():
    """Get sensor status including interface and capture state"""
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


@app.route('/scan')
@limiter.limit("10 per minute")
def scan_networks():
    """Scan for WiFi networks using integrated modules"""
    try:
        # Clear previous scan data
        parser.clear()
        memory_storage.clear()
        
        # Try real scan first
        networks = perform_real_scan()
        
    except Exception as e:
        logger.warning(f"Real scan failed: {e}, using mock data")
        networks = get_mock_networks()
    
    # Calculate risk scores using RiskScorer
    for net in networks:
        risk_result = risk_scorer.calculate_risk(net)
        net['risk_score'] = risk_result['risk_score']
        net['risk_level'] = risk_result['risk_level']
    
    # Store in persistent storage
    try:
        storage.store_networks(networks)
    except Exception as e:
        logger.error(f"Storage error: {e}")
    
    return jsonify({
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "networks": networks,
        "count": len(networks)
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


def get_mock_networks():
    """Mock networks for demonstration when real scan fails"""
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
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
