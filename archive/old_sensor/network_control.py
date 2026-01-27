import subprocess
import time
import logging
import os

logger = logging.getLogger(__name__)

class NetworkController:
    def __init__(self, interface="wlan0"):
        self.interface = interface

    def execute_command(self, cmd_list):
        """Execute system command and return success status"""
        try:
            subprocess.run(cmd_list, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd_list)} - Error: {e.stderr.decode()}")
            return False

    def enable_monitor_mode(self):
        """Switch interface to monitor mode"""
        logger.info(f"Enabling monitor mode on {self.interface}...")
        
        # Sequence: Down -> Set Monitor -> Up
        steps = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "type", "monitor"],
            ["ip", "link", "set", self.interface, "up"]
        ]

        for step in steps:
            if not self.execute_command(step):
                return False
        
        return True

    def disable_monitor_mode(self):
        """Switch interface back to managed mode"""
        logger.info(f"Disabling monitor mode on {self.interface}...")
        
        steps = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "type", "managed"],
            ["ip", "link", "set", self.interface, "up"]
        ]
        
        for step in steps:
            if not self.execute_command(step):
                return False
                
        return True

    def set_channel(self, channel):
        """Set WiFi channel"""
        # logger.debug(f"Switching {self.interface} to channel {channel}")
        cmd = ["iw", "dev", self.interface, "set", "channel", str(channel)]
        return self.execute_command(cmd)

    def is_interface_up(self):
        """Check if interface exists and is up"""
        try:
            output = subprocess.check_output(["ip", "link", "show", self.interface]).decode()
            return "state UP" in output
        except Exception:
            return False
