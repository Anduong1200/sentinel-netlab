import socket
import threading
import json
import logging

logger = logging.getLogger(__name__)

class SensorClient:
    def __init__(self, host='localhost', port=8888, callback_func=None):
        self.host = host
        self.port = port
        self.callback = callback_func
        self.sock = None
        self.running = False
        self.receive_thread = None

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.running = True
            
            # Start listener thread
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            return True, "Connected"
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False, str(e)

    def disconnect(self):
        self.running = False
        if self.sock:
            try:
                self.send_command("EXIT")
                self.sock.close()
            except:
                pass
            self.sock = None

    def send_command(self, cmd):
        if self.sock:
            try:
                self.sock.sendall(cmd.encode('utf-8'))
                return True
            except Exception as e:
                logger.error(f"Send error: {e}")
                return False
        return False

    def _receive_loop(self):
        buffer = ""
        while self.running and self.sock:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                
                buffer += data.decode('utf-8')
                
                # Handle stream fragmentation/concatenation
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip(): continue
                    
                    try:
                        json_data = json.loads(line)
                        if self.callback:
                            self.callback(json_data)
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON Parse Error: {e} - Line: {line}")
                        
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break
        
        self.running = False
        if self.callback:
            self.callback({"status": "disconnected", "message": "Connection lost"})
