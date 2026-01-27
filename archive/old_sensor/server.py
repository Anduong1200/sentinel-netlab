import socket
import threading
import json
import logging
import signal
import sys
import time
from scapy.all import AsyncSniffer

from network_control import NetworkController
from packet_handler import PacketHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WLAN_Sensor")

HOST = '0.0.0.0'
PORT = 8888

class SensorServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.client_socket = None
        
        # Initialize sub-modules
        self.controller = NetworkController(interface="wlan0") # Handle interface dynamic later
        self.packet_handler = PacketHandler()
        self.sniffer = None
        self.is_scanning = False

    def start(self):
        try:
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(1)
            self.running = True
            logger.info(f"Sensor Server started on {HOST}:{PORT}")
            
            while self.running:
                try:
                    logger.info("Waiting for client connection...")
                    client, addr = self.server_socket.accept()
                    logger.info(f"Connected to {addr}")
                    self.handle_client(client)
                except OSError:
                    break
                    
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop_scan()
            self.server_socket.close()

    def handle_client(self, client_sock):
        self.client_socket = client_sock
        with client_sock:
            while True:
                try:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    
                    try:
                        decoded = data.decode('utf-8').strip()
                        if not decoded: continue
                        
                        logger.info(f"Received command: {decoded}")
                        
                        # Handle multiple JSON objects stuck together
                        # Or just simple command parsing if it's not JSON
                        # For now, assume simple string commands or single JSON
                        
                        if decoded == "SCAN":
                            self.start_scan()
                            self.send_response({"status": "scanning_started", "message": "Scanning initiated"})
                        elif decoded == "STOP":
                            self.stop_scan()
                            self.send_response({"status": "scanning_stopped", "message": "Scanning stopped"})
                        elif decoded == "GET_DATA":
                            networks = self.packet_handler.get_networks()
                            self.send_response({"status": "data", "networks": networks})
                        elif decoded == "EXIT":
                            break
                        else:
                            self.send_response({"status": "error", "message": "Unknown command"})
                            
                    except Exception as parse_err:
                        logger.error(f"Command processing error: {parse_err}")
                        self.send_response({"status": "error", "message": str(parse_err)})

                except ConnectionResetError:
                    break
        
        logger.info("Client disconnected")
        self.stop_scan() # Stop scanning when client disconnects
        self.client_socket = None

    def send_response(self, data_dict):
        if self.client_socket:
            try:
                # Add newline delimiter for the client
                msg = json.dumps(data_dict) + "\n"
                self.client_socket.sendall(msg.encode('utf-8'))
            except Exception as e:
                logger.error(f"Send failed: {e}")

    def start_scan(self):
        if self.is_scanning:
            return

        # 1. Enable monitor mode
        if not self.controller.enable_monitor_mode():
            self.send_response({"status": "error", "message": "Failed to enable monitor mode"})
            return

        # 2. Start sniffer in a thread
        self.is_scanning = True
        self.packet_handler.clear()
        
        # Start Sniffer
        self.sniffer = AsyncSniffer(iface=self.controller.interface, prn=self.packet_handler.process_packet, store=False)
        self.sniffer.start()
        
        # Start Channel Hopper in background
        threading.Thread(target=self._channel_hopper, daemon=True).start()
        logger.info("Scan started")

    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            # Disable monitor mode (optional, maybe keep it on for speed)
            # self.controller.disable_monitor_mode() 
            logger.info("Scan stopped")

    def _channel_hopper(self):
        channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10]
        i = 0
        while self.is_scanning:
            ch = channels[i % len(channels)]
            self.controller.set_channel(ch)
            i += 1
            time.sleep(0.5) # Hop every 0.5s

    def shutdown(self, signum, frame):
        logger.info("Shutting down server...")
        self.running = False
        self.server_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    # Handle Ctrl+C
    server = SensorServer()
    signal.signal(signal.SIGINT, server.shutdown)
    server.start()
