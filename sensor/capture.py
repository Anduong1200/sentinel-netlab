#!/usr/bin/env python3
"""
WiFi Capture Module - Monitor mode control and channel hopping
Run on Linux VM with compatible Wi-Fi adapter (e.g., TL-WN722N v1)
"""

import subprocess
import time
import threading
import logging
from typing import Optional, List, Callable
from scapy.all import AsyncSniffer, Dot11

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CaptureEngine:
    """
    Handles Wi-Fi capture operations including:
    - Monitor mode control
    - Channel hopping
    - Packet sniffing
    """
    
    # Default 2.4GHz channels (non-overlapping first)
    DEFAULT_CHANNELS = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
    QUICK_CHANNELS = [1, 6, 11]  # For fast scanning
    
    def __init__(self, interface: str = "wlan0"):
        """
        Initialize capture engine.
        
        Args:
            interface: Wireless interface name (default: wlan0)
        """
        self.interface = interface
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_capturing = False
        self.channel_hopper_thread: Optional[threading.Thread] = None
        self.current_channel = 1
        self.dwell_time = 0.4  # seconds per channel
        self.channels = self.QUICK_CHANNELS.copy()
        
    def check_interface_exists(self) -> bool:
        """Check if the wireless interface exists."""
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True, text=True, timeout=5
            )
            return self.interface in result.stdout
        except Exception as e:
            logger.error(f"Failed to check interface: {e}")
            return False
    
    def get_interface_mode(self) -> Optional[str]:
        """Get current interface mode (managed/monitor)."""
        try:
            result = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'type' in line:
                    return line.split()[-1]  # e.g., 'monitor' or 'managed'
            return None
        except Exception as e:
            logger.error(f"Failed to get interface mode: {e}")
            return None
    
    def enable_monitor_mode(self) -> bool:
        """
        Enable monitor mode on the wireless interface.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if already in monitor mode
            current_mode = self.get_interface_mode()
            if current_mode == "monitor":
                logger.info(f"{self.interface} already in monitor mode")
                return True
            
            # Bring interface down
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                check=True, timeout=5
            )
            
            # Set monitor mode
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "monitor"],
                check=True, timeout=5
            )
            
            # Bring interface up
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=True, timeout=5
            )
            
            # Verify
            if self.get_interface_mode() == "monitor":
                logger.info(f"Monitor mode enabled on {self.interface}")
                return True
            else:
                logger.error("Failed to verify monitor mode")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable monitor mode: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error enabling monitor mode: {e}")
            return False
    
    def disable_monitor_mode(self) -> bool:
        """
        Disable monitor mode and return to managed mode.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                check=True, timeout=5
            )
            subprocess.run(
                ["iw", "dev", self.interface, "set", "type", "managed"],
                check=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=True, timeout=5
            )
            logger.info(f"Monitor mode disabled on {self.interface}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable monitor mode: {e}")
            return False
    
    def set_channel(self, channel: int) -> bool:
        """
        Set the wireless interface to a specific channel.
        
        Args:
            channel: Channel number (1-14 for 2.4GHz)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, timeout=5
            )
            self.current_channel = channel
            return True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to set channel {channel}: {e}")
            return False
    
    def _channel_hopper(self):
        """Background thread for channel hopping."""
        channel_idx = 0
        while self.is_capturing:
            channel = self.channels[channel_idx % len(self.channels)]
            self.set_channel(channel)
            channel_idx += 1
            time.sleep(self.dwell_time)
    
    def start_capture(
        self, 
        packet_callback: Callable,
        channels: Optional[List[int]] = None,
        dwell_time: float = 0.4,
        enable_channel_hop: bool = True
    ) -> bool:
        """
        Start packet capture with optional channel hopping.
        
        Args:
            packet_callback: Function to call for each captured packet
            channels: List of channels to hop (default: [1, 6, 11])
            dwell_time: Time to stay on each channel in seconds
            enable_channel_hop: Whether to enable channel hopping
            
        Returns:
            True if capture started successfully
        """
        if self.is_capturing:
            logger.warning("Capture already running")
            return False
        
        # Configure
        self.channels = channels or self.QUICK_CHANNELS.copy()
        self.dwell_time = dwell_time
        
        # Enable monitor mode if needed
        if self.get_interface_mode() != "monitor":
            if not self.enable_monitor_mode():
                logger.error("Cannot start capture without monitor mode")
                return False
        
        # Start sniffer
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=packet_callback,
                store=False,
                filter="type mgt or (wlan type data and ether proto 0x888e)"  # Mgt + EAPOL (Handshake)
            )
            self.sniffer.start()
            self.is_capturing = True
            logger.info(f"Capture started on {self.interface}")
            
            # Start channel hopping
            if enable_channel_hop:
                self.channel_hopper_thread = threading.Thread(
                    target=self._channel_hopper, 
                    daemon=True
                )
                self.channel_hopper_thread.start()
                logger.info(f"Channel hopping started: {self.channels}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            self.is_capturing = False
            return False
    
    def stop_capture(self):
        """Stop packet capture."""
        self.is_capturing = False
        
        if self.sniffer:
            try:
                self.sniffer.stop()
                self.sniffer = None
            except Exception as e:
                logger.warning(f"Error stopping sniffer: {e}")
        
        # Wait for channel hopper to stop
        if self.channel_hopper_thread and self.channel_hopper_thread.is_alive():
            self.channel_hopper_thread.join(timeout=2)
        
        logger.info("Capture stopped")
    
    def get_current_channel(self) -> int:
        """Get the current channel."""
        return self.current_channel

    def inject_frame(self, packet) -> bool:
        """
        Inject a raw frame into the interface.
        
        Args:
            packet: Scapy packet to send
            
        Returns:
            True if sent successfully
        """
        try:
            from scapy.all import sendp
            sendp(packet, iface=self.interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"Injection failed: {e}")
            return False

    def get_status(self) -> dict:
        """Get current capture status."""
        return {
            "interface": self.interface,
            "mode": self.get_interface_mode(),
            "is_capturing": self.is_capturing,
            "current_channel": self.current_channel,
            "channels": self.channels,
            "dwell_time": self.dwell_time
        }


# Convenience functions for standalone use
def check_monitor_support(interface: str = "wlan0") -> dict:
    """
    Check if the interface supports monitor mode.
    
    Returns:
        Dictionary with interface info and recommendations
    """
    result = {
        "interface": interface,
        "exists": False,
        "current_mode": None,
        "monitor_capable": False,
        "recommendations": []
    }
    
    engine = CaptureEngine(interface)
    
    # Check existence
    result["exists"] = engine.check_interface_exists()
    if not result["exists"]:
        result["recommendations"].append(
            f"Interface {interface} not found. Check USB passthrough and driver."
        )
        return result
    
    # Check current mode
    result["current_mode"] = engine.get_interface_mode()
    
    # Try to enable monitor mode
    if engine.enable_monitor_mode():
        result["monitor_capable"] = True
        engine.disable_monitor_mode()  # Restore
    else:
        result["recommendations"].append(
            "Cannot enable monitor mode. Check driver compatibility."
        )
    
    return result


if __name__ == "__main__":
    # Test module
    print("=" * 50)
    print("WiFi Capture Module Test")
    print("=" * 50)
    
    result = check_monitor_support("wlan0")
    print(f"Interface: {result['interface']}")
    print(f"Exists: {result['exists']}")
    print(f"Current Mode: {result['current_mode']}")
    print(f"Monitor Capable: {result['monitor_capable']}")
    
    if result["recommendations"]:
        print("\nRecommendations:")
        for rec in result["recommendations"]:
            print(f"  - {rec}")
