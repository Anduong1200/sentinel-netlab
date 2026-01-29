#!/usr/bin/env python3
"""
Sentinel NetLab - Bluetooth Sensor
Discovers nearby Bluetooth and BLE devices.
"""

import logging
import time
import json
from dataclasses import dataclass, asdict
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

@dataclass
class BluetoothDevice:
    address: str
    name: str | None
    class_of_device: int | None
    rssi: int | None
    last_seen: str
    is_ble: bool = False

class BluetoothSensor:
    """
    Scans for Bluetooth (Classic) and BLE devices.
    Requires pybluez and/or bleak.
    """
    
    def __init__(self, sensor_id: str, mock: bool = False):
        self.sensor_id = sensor_id
        self.mock = mock
        self.devices: dict[str, BluetoothDevice] = {}
        
    def scan(self, duration: int = 10):
        """Perform a Bluetooth scan"""
        if self.mock:
            self._mock_scan()
            return self.devices

        try:
            import bluetooth # pybluez
            logger.info("Starting Bluetooth Classic scan...")
            nearby_devices = bluetooth.discover_devices(duration=duration, lookup_names=True, flush_cache=True, lookup_class=True)
            
            for addr, name, device_class in nearby_devices:
                self.devices[addr] = BluetoothDevice(
                    address=addr,
                    name=name,
                    class_of_device=device_class,
                    rssi=None,
                    last_seen=datetime.now(UTC).isoformat()
                )
        except ImportError:
            logger.error("pybluez not installed. Install with: pip install pybluez")
        except Exception as e:
            logger.error(f"Bluetooth scan failed: {e}")
            
        return self.devices

    def _mock_scan(self):
        """Generate mock Bluetooth data"""
        import random
        mock_devices = [
            ("00:11:22:33:44:55", "Attacker Phone", 0x5a020c),
            ("AA:BB:CC:DD:EE:FF", "Victim Laptop", 0x10010c),
            ("66:77:88:99:AA:BB", "Unknown BLE Tag", None)
        ]
        
        for addr, name, dev_class in mock_devices:
            self.devices[addr] = BluetoothDevice(
                address=addr,
                name=name,
                class_of_device=dev_class,
                rssi=random.randint(-90, -30),
                last_seen=datetime.now(UTC).isoformat(),
                is_ble=(dev_class is None)
            )

    def save_results(self, path: str = "bluetooth_log.json"):
        """Save discovered devices to file"""
        data = {
            "sensor_id": self.sensor_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "devices": [asdict(d) for d in self.devices.values()]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Bluetooth results saved to {path}")

if __name__ == "__main__":
    sensor = BluetoothSensor(sensor_id="test-sensor", mock=True)
    results = sensor.scan()
    print(f"Discovered {len(results)} Bluetooth devices.")
    sensor.save_results()
