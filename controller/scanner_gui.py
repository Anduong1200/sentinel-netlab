#!/usr/bin/env python3
"""
WiFi Scanner GUI - Run on Windows
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import json
from datetime import datetime
import threading
import queue
import logging

# Basic logging just in case
logging.basicConfig(level=logging.INFO)

class WiFiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Scanner - Student Project")
        self.root.geometry("1000x700")
        
        # Configuration
        # Default to localhost for testing (User can change in settings)
        self.api_url = "http://127.0.0.1:5000"  
        self.api_key = "sentinel-dev-2024"
        
        # Data storage
        self.networks = []
        self.message_queue = queue.Queue()
        
        # Setup UI
        self.setup_ui()
        
        # Start queue processor
        self.process_queue()
        
        # Test connection
        self.test_connection()
    
    def setup_ui(self):
        """Setup the GUI interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="WiFi Security Scanner - Hybrid Architecture (VM + Windows)",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="10")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Control buttons
        ttk.Button(
            control_frame,
            text="🚀 Start Scan",
            command=self.start_scan,
            width=20
        ).grid(row=0, column=0, pady=5)
        
        ttk.Button(
            control_frame,
            text="📊 View History",
            command=self.view_history,
            width=20
        ).grid(row=1, column=0, pady=5)
        
        ttk.Button(
            control_frame,
            text="💾 Export CSV",
            command=self.export_csv,
            width=20
        ).grid(row=2, column=0, pady=5)
        
        ttk.Button(
            control_frame,
            text="📈 Risk Report",
            command=self.show_report,
            width=20
        ).grid(row=3, column=0, pady=5)
        
        ttk.Button(
            control_frame,
            text="⚙️ Settings",
            command=self.show_settings,
            width=20
        ).grid(row=4, column=0, pady=5)
        
        # Network List
        list_frame = ttk.LabelFrame(main_frame, text="Discovered Networks", padding="10")
        list_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Treeview for networks
        columns = ("SSID", "BSSID", "Signal", "Channel", "Encryption", "Risk", "Status")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        col_widths = [150, 180, 80, 80, 100, 80, 100]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Log Panel
        log_frame = ttk.LabelFrame(main_frame, text="System Log", padding="10")
        log_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
    
    def log_message(self, message, level="INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": "black",
            "SUCCESS": "green",
            "ERROR": "red",
            "WARNING": "orange"
        }.get(level, "black")
        
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.tag_config(level, foreground=color)
        self.log_text.see(tk.END)
        
        # Also update status bar
        self.status_var.set(message)
    
    def test_connection(self):
        """Test connection to VM API"""
        def test():
            try:
                response = requests.get(f"{self.api_url}/health", timeout=3)
                if response.status_code == 200:
                    self.message_queue.put(("SUCCESS", "✅ Connected to VM sensor"))
                else:
                    self.message_queue.put(("ERROR", "❌ Cannot connect to VM"))
            except Exception as e:
                self.message_queue.put(("ERROR", f"❌ Connection failed: {str(e)}"))
        
        threading.Thread(target=test, daemon=True).start()
    
    def start_scan(self):
        """Start network scan"""
        self.log_message("Starting network scan...", "INFO")
        
        def scan():
            try:
                headers = {"X-API-Key": self.api_key}
                response = requests.get(f"{self.api_url}/scan", headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    self.networks = data.get("networks", [])
                    self.message_queue.put(("NETWORKS", self.networks))
                    self.message_queue.put(("SUCCESS", f"Found {len(self.networks)} networks"))
                else:
                    self.message_queue.put(("ERROR", f"Scan failed: {response.status_code}"))
                    
            except Exception as e:
                self.message_queue.put(("ERROR", f"Scan error: {str(e)}"))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def view_history(self):
        """View scan history"""
        def get_history():
            try:
                headers = {"X-API-Key": self.api_key}
                response = requests.get(f"{self.api_url}/history", headers=headers, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    networks = data.get("networks", [])
                    self.message_queue.put(("NETWORKS", networks))
                    self.message_queue.put(("SUCCESS", f"Loaded {len(networks)} historical entries"))
                else:
                    self.message_queue.put(("ERROR", "Failed to load history"))
                    
            except Exception as e:
                self.message_queue.put(("ERROR", f"History error: {str(e)}"))
        
        threading.Thread(target=get_history, daemon=True).start()
    
    def export_csv(self):
        """Export scan data as CSV"""
        try:
            headers = {"X-API-Key": self.api_key}
            response = requests.get(f"{self.api_url}/export/csv", headers=headers, timeout=10)
            
            if response.status_code == 200:
                filename = f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                self.log_message(f"Exported to {filename}", "SUCCESS")
                messagebox.showinfo("Export Successful", f"Data saved to {filename}")
            else:
                self.log_message("Export failed", "ERROR")
                
        except Exception as e:
            self.log_message(f"Export error: {str(e)}", "ERROR")
    
    def show_report(self):
        """Show risk assessment report"""
        if not self.networks:
            messagebox.showwarning("No Data", "Please scan networks first")
            return
        
        # Count by risk level
        high = sum(1 for n in self.networks if n.get('risk_score', 0) >= 70)
        medium = sum(1 for n in self.networks if 40 <= n.get('risk_score', 0) < 70)
        low = sum(1 for n in self.networks if n.get('risk_score', 0) < 40)
        
        report = f"""
        === WiFi SECURITY REPORT ===
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Total Networks: {len(self.networks)}
        High Risk (>=70%): {high} 🔴
        Medium Risk (40-69%): {medium} 🟡
        Low Risk (<40%): {low} 🟢
        
        RECOMMENDATIONS:
        1. Change default SSIDs
        2. Use WPA3 or WPA2 with strong passwords
        3. Disable WPS if enabled
        4. Regularly update router firmware
        """
        
        # Show in new window
        report_window = tk.Toplevel(self.root)
        report_window.title("Security Report")
        report_window.geometry("500x400")
        
        text = scrolledtext.ScrolledText(report_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, report)
        text.config(state=tk.DISABLED)
        
        ttk.Button(report_window, text="Save Report", 
                  command=lambda: self.save_report(report)).pack(pady=10)
    
    def show_settings(self):
        """Show settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        
        ttk.Label(settings_window, text="VM Sensor Settings", font=("Arial", 12, "bold")).pack(pady=10)
        
        # API URL
        ttk.Label(settings_window, text="API URL:").pack(anchor=tk.W, padx=20)
        url_entry = ttk.Entry(settings_window, width=40)
        url_entry.insert(0, self.api_url)
        url_entry.pack(padx=20, pady=5)
        
        # API Key
        ttk.Label(settings_window, text="API Key:").pack(anchor=tk.W, padx=20)
        key_entry = ttk.Entry(settings_window, width=40)
        key_entry.insert(0, self.api_key)
        key_entry.pack(padx=20, pady=5)
        
        def save_settings():
            self.api_url = url_entry.get()
            self.api_key = key_entry.get()
            self.log_message("Settings saved", "SUCCESS")
            settings_window.destroy()
            # Retry connection with new settings
            self.test_connection()
        
        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=20)
    
    def save_report(self, report):
        """Save report to file"""
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        self.log_message(f"Report saved to {filename}", "SUCCESS")
    
    def process_queue(self):
        """Process messages from queue (thread-safe)"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == "NETWORKS":
                    self.display_networks(data)
                elif msg_type in ["INFO", "SUCCESS", "ERROR", "WARNING"]:
                    self.log_message(data, msg_type)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def display_networks(self, networks):
        """Display networks in treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add networks
        for net in networks:
            risk = net.get('risk_score', 0)
            
            # Determine risk color
            if risk >= 70:
                risk_text = f"🔴 {risk}%"
                status = "HIGH RISK"
            elif risk >= 40:
                risk_text = f"🟡 {risk}%"
                status = "MEDIUM RISK"
            else:
                risk_text = f"🟢 {risk}%"
                status = "LOW RISK"
            
            self.tree.insert("", tk.END, values=(
                net.get('ssid', 'Unknown'),
                net.get('bssid', 'Unknown'),
                f"{net.get('signal', 0)} dBm",
                net.get('channel', 0),
                net.get('encryption', 'Unknown'),
                risk_text,
                status
            ))

def main():
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
