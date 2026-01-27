#!/usr/bin/env python3
"""
USB Watchdog - Monitor USB WiFi Adapter Connection
Auto-detects disconnection and attempts recovery.
"""

import subprocess
import threading
import time
import logging
import os
import sys
from typing import Optional, Callable, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class USBWatchdog:
    """
    Monitors USB WiFi adapter connectivity.
    Detects disconnection and triggers recovery actions.
    """
    
    def __init__(
        self,
        interface: str = "wlan0",
        check_interval: float = 2.0,
        on_disconnect: Optional[Callable] = None,
        on_reconnect: Optional[Callable] = None,
        auto_recover: bool = True
    ):
        """
        Initialize USB Watchdog.
        
        Args:
            interface: Wireless interface to monitor
            check_interval: Seconds between checks
            on_disconnect: Callback when adapter disconnects
            on_reconnect: Callback when adapter reconnects
            auto_recover: Attempt automatic driver reload
        """
        self.interface = interface
        self.check_interval = check_interval
        self.on_disconnect = on_disconnect
        self.on_reconnect = on_reconnect
        self.auto_recover = auto_recover
        
        self.running = False
        self.connected = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        self.stats = {
            "disconnect_count": 0,
            "reconnect_count": 0,
            "recovery_attempts": 0,
            "last_disconnect": None,
            "last_reconnect": None,
            "uptime_seconds": 0
        }
        self._start_time = None
        
    def check_interface_exists(self) -> bool:
        """Check if wireless interface exists."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_monitor_mode(self) -> bool:
        """Check if interface is in monitor mode."""
        try:
            result = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            return "monitor" in result.stdout.lower()
        except Exception:
            return False
    
    def get_driver_info(self) -> Optional[str]:
        """Get driver name for the interface."""
        try:
            # Read from sysfs
            driver_path = f"/sys/class/net/{self.interface}/device/driver"
            if os.path.exists(driver_path):
                return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass
        return None
    
    def reload_driver(self) -> bool:
        """Attempt to reload the driver."""
        driver = self.get_driver_info()
        if not driver:
            logger.warning("Cannot determine driver name")
            return False
            
        try:
            logger.info(f"Reloading driver: {driver}")
            subprocess.run(["modprobe", "-r", driver], timeout=10)
            time.sleep(1)
            subprocess.run(["modprobe", driver], timeout=10)
            time.sleep(2)
            
            self.stats["recovery_attempts"] += 1
            return self.check_interface_exists()
            
        except Exception as e:
            logger.error(f"Driver reload failed: {e}")
            return False
    
    def _monitor_loop(self):
        """Background monitoring thread."""
        was_connected = self.check_interface_exists()
        self.connected = was_connected
        
        while self.running:
            time.sleep(self.check_interval)
            
            is_connected = self.check_interface_exists()
            
            # Detect disconnect
            if was_connected and not is_connected:
                self.connected = False
                self.stats["disconnect_count"] += 1
                self.stats["last_disconnect"] = time.strftime("%Y-%m-%d %H:%M:%S")
                
                logger.warning(f"🔴 USB adapter disconnected: {self.interface}")
                
                if self.on_disconnect:
                    self.on_disconnect()
                
                # Auto recovery
                if self.auto_recover:
                    logger.info("Attempting auto-recovery...")
                    time.sleep(3)  # Wait for USB to settle
                    
                    for attempt in range(3):
                        if self.check_interface_exists():
                            break
                        logger.info(f"Recovery attempt {attempt + 1}/3...")
                        self.reload_driver()
                        time.sleep(2)
            
            # Detect reconnect
            elif not was_connected and is_connected:
                self.connected = True
                self.stats["reconnect_count"] += 1
                self.stats["last_reconnect"] = time.strftime("%Y-%m-%d %H:%M:%S")
                
                logger.info(f"🟢 USB adapter reconnected: {self.interface}")
                
                if self.on_reconnect:
                    self.on_reconnect()
            
            was_connected = is_connected
            
            # Update uptime
            if self._start_time and self.connected:
                self.stats["uptime_seconds"] = int(time.time() - self._start_time)
    
    def start(self):
        """Start watchdog monitoring."""
        if self.running:
            return
            
        self.running = True
        self._start_time = time.time()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"USB Watchdog started for {self.interface}")
    
    def stop(self):
        """Stop watchdog monitoring."""
        self.running = False
        logger.info("USB Watchdog stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get watchdog status."""
        return {
            "interface": self.interface,
            "connected": self.connected,
            "in_monitor_mode": self.check_monitor_mode() if self.connected else False,
            "driver": self.get_driver_info() if self.connected else None,
            "auto_recover": self.auto_recover,
            "stats": self.stats
        }


def play_alert_sound():
    """Play alert sound (requires paplay or aplay)."""
    try:
        # Try to play a beep
        subprocess.run(["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"], 
                      timeout=2, capture_output=True)
    except:
        try:
            # Fallback to beep
            subprocess.run(["beep", "-f", "1000", "-l", "500"], timeout=2, capture_output=True)
        except:
            pass


if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="USB WiFi Watchdog CLI")
    parser.add_argument("-i", "--interface", default="wlan0", help="Wireless interface")
    parser.add_argument("-t", "--interval", type=float, default=2.0, help="Check interval (seconds)")
    parser.add_argument("--no-auto-recover", action="store_true", help="Disable auto recovery")
    parser.add_argument("--alert-sound", action="store_true", help="Play sound on disconnect")
    parser.add_argument("--status", action="store_true", help="Show current status and exit")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("USB WiFi Watchdog")
    print("=" * 50)
    
    def on_disconnect():
        print("\n⚠️  ALERT: USB adapter disconnected!")
        if args.alert_sound:
            play_alert_sound()
    
    def on_reconnect():
        print("\n✅ USB adapter reconnected!")
    
    watchdog = USBWatchdog(
        interface=args.interface,
        check_interval=args.interval,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        auto_recover=not args.no_auto_recover
    )
    
    if args.status:
        status = watchdog.get_status()
        print(json.dumps(status, indent=2))
        sys.exit(0)
    
    print(f"Monitoring: {args.interface}")
    print(f"Interval: {args.interval}s")
    print(f"Auto-recover: {not args.no_auto_recover}")
    print("-" * 50)
    print("Press Ctrl+C to stop")
    print()
    
    watchdog.start()
    
    try:
        while True:
            time.sleep(10)
            status = watchdog.get_status()
            state = "🟢 Connected" if status["connected"] else "🔴 Disconnected"
            print(f"[{time.strftime('%H:%M:%S')}] {state} | Uptime: {status['stats']['uptime_seconds']}s | Disconnects: {status['stats']['disconnect_count']}")
    except KeyboardInterrupt:
        pass
    
    watchdog.stop()
    print("\nFinal stats:", json.dumps(watchdog.get_status()["stats"], indent=2))
