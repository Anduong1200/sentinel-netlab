#!/usr/bin/env python3
"""
Sentinel NetLab Sensor - CLI Entry Point
Validates flags, loads config, and starts sensor controller.
"""

import sys
import yaml
import logging
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

# Setup path
SENSOR_DIR = Path(__file__).parent
sys.path.insert(0, str(SENSOR_DIR))


def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if config_file and Path(config_file).exists():
        with open(config_file) as f:
            return yaml.safe_load(f)
    
    # Try default locations
    default_paths = [
        SENSOR_DIR / "config.yaml",
        Path("/etc/sentinel/config.yaml"),
        Path.home() / ".sentinel/config.yaml"
    ]
    
    for path in default_paths:
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)
    
    return {}


def validate_preconditions(args: argparse.Namespace) -> bool:
    """Validate required preconditions before starting"""
    errors = []
    
    # Check sensor_id
    if not args.sensor_id:
        errors.append("--sensor-id is required")
    
    # Check interface (unless mock mode)
    if not args.mock_mode:
        if not args.iface:
            errors.append("--iface is required (or use --mock-mode)")
        elif not args.mock_mode:
            # Check if interface exists (Linux only)
            if sys.platform.startswith('linux'):
                if not Path(f"/sys/class/net/{args.iface}").exists():
                    errors.append(f"Interface {args.iface} not found")
    
    # Check upload URL format
    if args.upload_url:
        if not args.upload_url.startswith(('http://', 'https://')):
            errors.append("--upload-url must start with http:// or https://")
    
    # Check channels format
    if args.channels:
        try:
            channels = [int(c.strip()) for c in args.channels.split(',')]
            for ch in channels:
                if not (1 <= ch <= 165):
                    errors.append(f"Invalid channel: {ch}")
        except ValueError:
            errors.append("--channels must be comma-separated integers")
    
    # Print errors and return
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return False
    
    return True


def merge_config(args: argparse.Namespace, file_config: Dict) -> Dict[str, Any]:
    """Merge CLI args with file config (CLI takes precedence)"""
    config = {
        'sensor': {
            'id': args.sensor_id or file_config.get('sensor', {}).get('id', 'sensor-01'),
            'interface': args.iface or file_config.get('sensor', {}).get('interface', 'wlan0'),
        },
        'capture': {
            'method': 'mock' if args.mock_mode else file_config.get('capture', {}).get('method', 'scapy'),
            'channels': (
                [int(c) for c in args.channels.split(',')] if args.channels
                else file_config.get('capture', {}).get('channels', [1, 6, 11])
            ),
            'dwell_ms': args.dwell_ms or file_config.get('capture', {}).get('dwell_ms', 200),
        },
        'buffer': {
            'max_items': file_config.get('buffer', {}).get('max_items', 10000),
            'storage_path': args.storage_path or file_config.get('buffer', {}).get('storage_path', '/var/lib/sentinel/journal'),
        },
        'transport': {
            'upload_url': args.upload_url or file_config.get('transport', {}).get('upload_url', 'http://localhost:5000/api/v1/telemetry'),
            'auth_token': args.auth_token or file_config.get('transport', {}).get('auth_token', 'sentinel-dev-2024'),
        },
        'upload': {
            'batch_size': args.batch_size or file_config.get('upload', {}).get('batch_size', 200),
            'interval_sec': args.upload_interval or file_config.get('upload', {}).get('interval_sec', 5.0),
        },
        'privacy': {
            'anonymize_ssid': args.anonymize_ssid or file_config.get('privacy', {}).get('anonymize_ssid', False),
        },
        'logging': {
            'level': args.log_level or file_config.get('logging', {}).get('level', 'INFO'),
        },
        'mock_mode': args.mock_mode,
    }
    return config


def setup_logging(level: str) -> None:
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def print_banner(config: Dict) -> None:
    """Print startup banner"""
    print("=" * 60)
    print("  Sentinel NetLab Sensor")
    print("  Lightweight Hybrid Wireless IDS")
    print("=" * 60)
    print(f"  Sensor ID:  {config['sensor']['id']}")
    print(f"  Interface:  {config['sensor']['interface']}")
    print(f"  Channels:   {config['capture']['channels']}")
    print(f"  Mock Mode:  {config['mock_mode']}")
    print(f"  Upload URL: {config['transport']['upload_url']}")
    print("=" * 60)


def main() -> int:
    """CLI main entry point"""
    parser = argparse.ArgumentParser(
        prog='sentinel-sensor',
        description='Sentinel NetLab Sensor - Wireless IDS Capture Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with real interface
  %(prog)s --sensor-id rpi-01 --iface wlan0mon
  
  # Mock mode for testing
  %(prog)s --sensor-id test-01 --iface mock0 --mock-mode
  
  # Custom channels and dwell time
  %(prog)s --sensor-id lab-01 --iface wlan0mon --channels 1,6,11 --dwell-ms 300
  
  # Use config file
  %(prog)s --config-file /etc/sentinel/config.yaml
        """
    )
    
    # Required
    parser.add_argument('--sensor-id', help='Unique sensor identifier')
    parser.add_argument('--iface', help='Network interface')
    
    # Capture
    parser.add_argument('--channels', help='Comma-separated channel list')
    parser.add_argument('--dwell-ms', type=int, help='Channel dwell time (ms)')
    
    # Batching
    parser.add_argument('--batch-size', type=int, help='Max items per batch')
    parser.add_argument('--upload-interval', type=float, help='Upload interval (sec)')
    
    # Transport
    parser.add_argument('--upload-url', help='Controller telemetry endpoint')
    parser.add_argument('--auth-token', help='Authentication token')
    
    # Storage
    parser.add_argument('--storage-path', help='Journal storage path')
    parser.add_argument('--max-disk-usage', type=int, help='Max disk MB for journals')
    
    # Mode
    parser.add_argument('--mock-mode', action='store_true', help='Use mock capture driver')
    parser.add_argument('--mode', choices=['capture', 'test'], default='capture',
                       help='Operation mode')
    
    # Privacy
    parser.add_argument('--anonymize-ssid', action='store_true', help='Hash SSIDs')
    
    # GPS
    parser.add_argument('--gps-device', help='GPS NMEA device path')
    
    # Sync
    parser.add_argument('--ntp-sync', action='store_true', help='Ensure NTP sync on start')
    
    # Logging
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level')
    
    # Config
    parser.add_argument('--config-file', help='YAML config file path')
    
    # Lab safety
    parser.add_argument('--confirm-lab-actions', action='store_true',
                       help='Confirm lab/attack actions')
    
    args = parser.parse_args()
    
    # Load config file
    file_config = load_config(args.config_file)
    
    # Validate
    if not validate_preconditions(args):
        return 1
    
    # Merge config
    config = merge_config(args, file_config)
    
    # Setup logging
    setup_logging(config['logging']['level'])
    
    # Print banner
    print_banner(config)
    
    # Import and start controller
    try:
        from sensor_controller import SensorController
        
        controller = SensorController(
            sensor_id=config['sensor']['id'],
            iface=config['sensor']['interface'],
            channels=config['capture']['channels'],
            dwell_ms=config['capture']['dwell_ms'],
            upload_url=config['transport']['upload_url'],
            auth_token=config['transport']['auth_token'],
            storage_path=config['buffer']['storage_path'],
            batch_size=config['upload']['batch_size'],
            upload_interval=config['upload']['interval_sec'],
            mock_mode=config['mock_mode'],
            anonymize_ssid=config['privacy']['anonymize_ssid']
        )
        
        if controller.start():
            print("\nSensor running. Press Ctrl+C to stop.\n")
            
            import signal
            import time
            
            def shutdown(sig, frame):
                print("\nShutting down...")
                controller.stop()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, shutdown)
            signal.signal(signal.SIGTERM, shutdown)
            
            while controller._running:
                time.sleep(1)
        else:
            print("ERROR: Failed to start sensor", file=sys.stderr)
            return 1
            
    except ImportError as e:
        print(f"ERROR: Failed to import sensor modules: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
