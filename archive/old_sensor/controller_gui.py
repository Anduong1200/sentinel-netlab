import tkinter as tk
from tkinter import messagebox, filedialog
import csv
import datetime
import logging
import queue
import time

from views import NetworkTable, ControlPanel
from client import SensorClient
from analyzer import SecurityAnalyzer

# Log to file and console
logging.basicConfig(level=logging.INFO, filename="controller.log", filemode="w",
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HybridControllerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hybrid WiFi Security Monitor (WSL2 + Windows)")
        self.geometry("900x600")
        
        self.sensor_client = SensorClient(callback_func=self.on_server_message)
        self.msg_queue = queue.Queue() # Thread-safe queue for GUI updates
        
        self.network_data_cache = {} # Store raw data for export

        # UI Layout
        self._init_ui()
        
        # Periodic GUI update check
        self.after(100, self.process_queue)

        # Connect on startup
        self.connect_to_server()

    def _init_ui(self):
        # Header
        header = tk.Label(self, text="WIRELESS SECURITY MONITORING SYSTEM", 
                         font=("Arial", 16, "bold"), bg="#333", fg="white", pady=10)
        header.pack(fill=tk.X)

        # Main Content
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Control Panel
        self.controls = ControlPanel(main_frame, callbacks={
            'scan': self.cmd_scan,
            'stop': self.cmd_stop,
            'export': self.cmd_export
        })
        self.controls.pack(fill=tk.X, pady=(0, 5))

        # Network Table
        self.table = NetworkTable(main_frame)
        self.table.pack(fill=tk.BOTH, expand=True)

    def connect_to_server(self):
        success, msg = self.sensor_client.connect()
        if success:
            self.controls.update_status("Connected to WSL2 Sensor")
        else:
            self.controls.update_status(f"Connection Failed: {msg}")
            messagebox.showerror("Connection Error", 
                                 f"Cannot connect to WSL2 Sensor at localhost:8888.\nMake sure 'server.py' is running in WSL2.\nError: {msg}")

    def on_server_message(self, data):
        """Callback from Client Thread. Put data in queue."""
        self.msg_queue.put(data)

    def process_queue(self):
        """Process messages from queue in Main Thread"""
        while not self.msg_queue.empty():
            data = self.msg_queue.get()
            self.handle_server_data(data)
        
        self.after(100, self.process_queue)

    def handle_server_data(self, data):
        status = data.get("status")
        
        if status == "data":
            networks = data.get("networks", [])
            # Update Table
            for net in networks:
                # Analyze Risk
                risk = SecurityAnalyzer.analyze_network(net['ssid'], net['encryption'], net['rssi'])
                self.table.update_network(net, risk)
                
                # Cache for export
                net['risk_level'] = risk['level']
                self.network_data_cache[net['bssid']] = net

        elif status == "scanning_started":
            self.controls.set_scanning_state(True)
            self.table.clear()
            self.network_data_cache = {}
            
        elif status == "scanning_stopped":
            self.controls.set_scanning_state(False)
            
        elif status == "error":
            messagebox.showerror("Sensor Error", data.get("message"))
            
        elif status == "disconnected":
            self.controls.update_status("Disconnected")
            self.controls.set_scanning_state(False)
            if messagebox.askretrycancel("Disconnected", "Connection to Sensor lost. Reconnect?"):
                self.connect_to_server()

    # --- Commands ---
    def cmd_scan(self):
        if self.sensor_client.send_command("SCAN"):
            self.controls.update_status("Requesting Scan...")
            # Automatically start data pulling? 
            # In 'server.py', SCAN starts putting data in packets? 
            # Or do we need to poll?
            # Based on my server implementation: server sends responses when it gets packets?
            # Wait, my server.py doesn't automatically push packet data back in the `process_packet` callback!
            
            # Correction: My server.py `process_packet` just updates `self.networks`.
            # I need to implement a polling mechanism or server-push.
            # Simpler update: I'll add a polling loop here or the server should stream.
            
            # For this PoC, let's use Polling.
            self.start_polling()

    def start_polling(self):
        self.polling = True
        self._poll_data()

    def _poll_data(self):
        if not hasattr(self, 'polling') or not self.polling: return
        self.sensor_client.send_command("GET_DATA")
        self.after(1000, self._poll_data) # Poll every 1s

    def cmd_stop(self):
        if self.sensor_client.send_command("STOP"):
            self.polling = False

    def cmd_export(self):
        if not self.network_data_cache:
            messagebox.showinfo("Export", "No data to export.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["SSID", "BSSID", "RSSI", "Channel", "Encryption", "Risk Level"])
                    for bssid, net in self.network_data_cache.items():
                        writer.writerow([
                            net.get('ssid'),
                            net.get('bssid'),
                            net.get('rssi'),
                            net.get('channel'),
                            net.get('encryption'),
                            net.get('risk_level')
                        ])
                messagebox.showinfo("Success", f"Data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def on_closing(self):
        self.polling = False
        self.sensor_client.disconnect()
        self.destroy()

if __name__ == "__main__":
    app = HybridControllerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
