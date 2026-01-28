#!/usr/bin/env python3
"""
Sensor CLI - Unified Command Line Interface
Combines all sensor features with toggleable options.
"""

import argparse
import logging
import os
import sys
import threading
import time

# Add sensor to path
# Add common to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.recommendations import generate_recommendations

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("sensor-cli")


class SensorCLI:
    """
    Unified CLI for all sensor features.
    """

    def __init__(self, args):
        self.args = args
        self.running = False

        # Components (lazy-loaded based on options)
        self.capture_engine = None
        self.parser = None
        self.storage = None
        self.risk_scorer = None
        self.evil_twin_detector = None
        self.watchdog = None
        self.api_thread = None

    def setup_capture_engine(self):
        """Initialize capture engine based on mode."""
        if self.args.engine == "tshark":
            from capture_tshark import TsharkCaptureEngine
            self.capture_engine = TsharkCaptureEngine(
                interface=self.args.interface,
                output_dir=self.args.pcap_dir
            )
            logger.info("Using Tshark capture engine (high-performance)")
        else:
            from capture import CaptureEngine
            self.capture_engine = CaptureEngine(interface=self.args.interface)
            logger.info("Using Scapy capture engine (standard)")

    def setup_storage(self):
        """Initialize storage based on mode."""
        if self.args.buffered_storage:
            from storage_buffered import BufferedStorage
            self.storage = BufferedStorage(
                db_path=self.args.db,
                buffer_size=self.args.buffer_size,
                flush_interval=self.args.flush_interval
            )
            self.storage.start()
            logger.info(
                f"Using buffered storage (buffer={self.args.buffer_size}, interval={self.args.flush_interval}s)")
        else:
            from storage import WiFiStorage
            self.storage = WiFiStorage(db_path=self.args.db)
            logger.info("Using standard storage")

    def setup_parser(self):
        """Initialize packet parser."""
        from parser import WiFiParser
        self.parser = WiFiParser()

    def setup_risk_scorer(self):
        """Initialize risk scorer."""
        from algos.evil_twin import AdvancedEvilTwinDetector
        from algos.risk import RiskScorer
        self.risk_scorer = RiskScorer()
        self.evil_twin_detector = AdvancedEvilTwinDetector()
        logger.info("Initialized Risk Scorer and Evil Twin Detector")

    def setup_watchdog(self):
        """Initialize USB watchdog if enabled."""
        if self.args.watchdog:
            from usb_watchdog import USBWatchdog

            def on_disconnect():
                logger.warning("USB adapter disconnected!")
                if self.capture_engine:
                    self.capture_engine.stop_capture()

            def on_reconnect():
                logger.info("USB adapter reconnected, restarting capture...")
                if self.capture_engine:
                    time.sleep(2)
                    self.capture_engine.enable_monitor_mode()
                    self.start_capture()

            self.watchdog = USBWatchdog(
                interface=self.args.interface,
                on_disconnect=on_disconnect,
                on_reconnect=on_reconnect,
                auto_recover=True
            )
            self.watchdog.start()
            logger.info("USB Watchdog enabled")

    def on_packet(self, packet):
        """Callback for captured packets."""
        try:
            result = self.parser.process_packet(packet)
            if result:
                # Calculate risk
                if "ssid" in result:
                    risk = self.risk_scorer.calculate_risk(result)
                    result["risk_score"] = risk["risk_score"]
                    result["risk_level"] = risk["risk_level"]

                    # Generate Advice
                    recs = generate_recommendations(result, risk)
                    result["recommendations"] = recs

                # Store
                if hasattr(self.storage, 'add_network'):
                    self.storage.add_network(result)
                elif hasattr(self.storage, 'save_network'):
                    self.storage.save_network(result)

                # Log
                if result.get("type") == "deauth_detected":
                    logger.warning(
                        f"🔴 Deauth: {result.get('sender')} -> {result.get('target')}")
                elif result.get("ssid"):
                    if self.args.verbose:
                        logger.info(
                            f"📶 {result['ssid'][:20]:20} | {result['bssid']} | Risk: {result.get('risk_score', '?')}")

                # Process Advanced Threat Detection (Evil Twin)
                if self.evil_twin_detector and "bssid" in result:
                    # Ingest into stateful detector
                    alerts = self.evil_twin_detector.ingest(result)

                    if alerts:
                        for alert in alerts:
                            logger.critical(f"⚠️ EVIL TWIN DETECTED: {alert.ssid} ({alert.suspect_bssid})")
                            # Add alert to result storage if possible
                            if hasattr(self.storage, 'add_event'):
                                self.storage.add_event({
                                    "type": "evil_twin",
                                    "severity": alert.severity,
                                    "details": alert.recommendation,
                                    "timestamp": alert.timestamp,
                                    "bssid": alert.suspect_bssid
                                })

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def start_capture(self):
        """Start packet capture."""
        channels = [int(c) for c in self.args.channels.split(",")]

        if hasattr(self.capture_engine, 'start_capture'):
            self.capture_engine.start_capture(
                packet_callback=self.on_packet,
                channels=channels,
                enable_channel_hop=not self.args.no_hop
            )

    def start_api(self):
        """Start API server in background thread."""
        if not self.args.api:
            return

        from flask import Flask, jsonify
        from flask_cors import CORS

        app = Flask(__name__)
        CORS(app)

        @app.route('/health')
        def health():
            return jsonify({"status": "ok"})

        @app.route('/status')
        def status():
            result = {
                "interface": self.args.interface,
                "engine": self.args.engine,
                "buffered_storage": self.args.buffered_storage,
                "watchdog": self.args.watchdog
            }
            if self.capture_engine:
                result["capture"] = self.capture_engine.get_status()
            if self.watchdog:
                result["usb"] = self.watchdog.get_status()
            if self.storage and hasattr(self.storage, 'get_stats'):
                result["storage"] = self.storage.get_stats()
            return jsonify(result)

        @app.route('/networks')
        def networks():
            if hasattr(self.storage, 'get_networks'):
                nets = self.storage.get_networks(limit=100)
                return jsonify({"networks": nets})
            return jsonify({"networks": list(self.parser.networks.values())})

        @app.route('/events')
        def events():
            if hasattr(self.storage, 'get_events'):
                return jsonify({"events": self.storage.get_events(limit=50)})
            return jsonify({"events": self.parser.security_events[-50:]})

        @app.route('/metrics')
        def metrics():
            from common.metrics import generate_latest_metrics
            data, content_type = generate_latest_metrics()
            return data, 200, {'Content-Type': content_type}

        def run_api():
            app.run(
                host=self.args.host,
                port=self.args.port,
                debug=False,
                use_reloader=False)

        self.api_thread = threading.Thread(target=run_api, daemon=True)
        self.api_thread.start()
        logger.info(
            f"API server started on http://{self.args.host}:{self.args.port}")

    def run(self):
        """Main run loop."""
        print("=" * 60)
        print("  Sentinel NetLab - Sensor CLI")
        print("=" * 60)

        # Setup components
        self.setup_capture_engine()
        self.setup_storage()
        self.setup_parser()
        self.setup_risk_scorer()
        self.setup_watchdog()

        # Enable monitor mode
        if not self.args.no_monitor:
            self.capture_engine.enable_monitor_mode()

        # Start API if requested
        self.start_api()

        # Start capture
        self.running = True
        self.start_capture()

        print("-" * 60)
        print(f"Interface: {self.args.interface}")
        print(f"Engine: {self.args.engine}")
        print(f"Channels: {self.args.channels}")
        print(f"Buffered Storage: {self.args.buffered_storage}")
        print(f"USB Watchdog: {self.args.watchdog}")
        print(
            f"API: {'http://' + self.args.host + ':' + str(self.args.port) if self.args.api else 'Disabled'}")
        print("-" * 60)
        print("Press Ctrl+C to stop")
        print()

        try:
            while self.running:
                time.sleep(5)

                # Print stats periodically
                if self.args.stats:
                    stats = self.parser.get_stats()
                    print(
                        f"[Stats] Networks: {stats['network_count']} | Packets: {stats['packet_count']} | Events: {len(self.parser.security_events)}")

        except KeyboardInterrupt:
            pass

        self.shutdown()

    def shutdown(self):
        """Clean shutdown."""
        print("\nShutting down...")
        self.running = False

        if self.capture_engine:
            self.capture_engine.stop_capture()

        if self.watchdog:
            self.watchdog.stop()

        if self.storage and hasattr(self.storage, 'stop'):
            self.storage.stop()

        print("Goodbye!")


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab Sensor CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with Scapy
  python sensor_cli.py -i wlan0

  # High-performance mode with Tshark
  python sensor_cli.py -i wlan0 --engine tshark --buffered-storage

  # Full feature set with API
  python sensor_cli.py -i wlan0 --engine tshark --buffered-storage --watchdog --api

  # Specific channels only
  python sensor_cli.py -i wlan0 -c 1,6,11,36,40
        """
    )

    # Interface options
    parser.add_argument(
        "-i",
        "--interface",
        default="wlan0",
        help="Wireless interface")
    parser.add_argument(
        "-c",
        "--channels",
        default="1,6,11",
        help="Channels to scan")
    parser.add_argument(
        "--no-hop",
        action="store_true",
        help="Disable channel hopping")
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="Skip monitor mode setup")

    # Engine options
    parser.add_argument(
        "--engine",
        choices=[
            "scapy",
            "tshark"],
        default="scapy",
        help="Capture engine (scapy=standard, tshark=high-performance)")
    parser.add_argument(
        "--pcap-dir",
        default="/tmp/captures",
        help="PCAP output directory")

    # Storage options
    parser.add_argument(
        "--db",
        default="wifi_scanner.db",
        help="Database path")
    parser.add_argument(
        "--buffered-storage",
        action="store_true",
        help="Enable buffered batch writes")
    parser.add_argument(
        "--buffer-size",
        type=int,
        default=100,
        help="Buffer size for batch writes")
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=5.0,
        help="Flush interval (seconds)")

    # Watchdog options
    parser.add_argument(
        "--watchdog",
        action="store_true",
        help="Enable USB watchdog")

    # API options
    parser.add_argument("--api", action="store_true", help="Enable REST API")
    parser.add_argument("--host", default="0.0.0.0", help="API host")
    parser.add_argument("--port", type=int, default=5000, help="API port")

    # Output options
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output")
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show periodic stats")

    args = parser.parse_args()

    cli = SensorCLI(args)
    cli.run()


if __name__ == "__main__":
    main()
