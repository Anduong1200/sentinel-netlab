import tkinter as tk
from tkinter import ttk

class NetworkTable(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        
        # Define columns
        cols = ("SSID", "BSSID", "RSSI", "Channel", "Encryption", "Risk")
        self.tree = ttk.Treeview(self, columns=cols, show='headings', selectmode="browse")
        
        # Define headings and column widths
        self.tree.heading("SSID", text="SSID")
        self.tree.column("SSID", width=150)
        
        self.tree.heading("BSSID", text="BSSID")
        self.tree.column("BSSID", width=120)
        
        self.tree.heading("RSSI", text="Signal (dBm)")
        self.tree.column("RSSI", width=80, anchor="center")

        self.tree.heading("Channel", text="CH")
        self.tree.column("Channel", width=50, anchor="center")

        self.tree.heading("Encryption", text="Encryption")
        self.tree.column("Encryption", width=100)

        self.tree.heading("Risk", text="Risk Level")
        self.tree.column("Risk", width=100, anchor="center")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Tag configuration for colors
        self.tree.tag_configure("red", background="#ffcccc")      # High Risk
        self.tree.tag_configure("orange", background="#ffe4b5")   # Medium Risk
        self.tree.tag_configure("green", background="#ccffcc")    # Low Risk
        self.tree.tag_configure("yellow", background="#ffffcc")   # Unknown

    def update_network(self, network_data, risk_data):
        """Update or Insert network into treeview"""
        bssid = network_data.get("bssid")
        if not bssid: return

        values = (
            network_data.get("ssid"),
            bssid,
            network_data.get("rssi"),
            network_data.get("channel"),
            network_data.get("encryption"),
            risk_data.get("level")
        )
        
        # Determine color tag
        tag = risk_data.get("color", "white")

        if self.tree.exists(bssid):
            # Update existing
            self.tree.item(bssid, values=values, tags=(tag,))
        else:
            # Insert new
            self.tree.insert("", "end", iid=bssid, values=values, tags=(tag,))

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

class ControlPanel(ttk.Frame):
    def __init__(self, parent, callbacks):
        super().__init__(parent, padding=10)
        self.callbacks = callbacks # cmd_scan, cmd_stop, cmd_export

        self.btn_scan = ttk.Button(self, text="Start Scan", command=self.callbacks.get('scan'))
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(self, text="Stop Scan", command=self.callbacks.get('stop'))
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        self.btn_stop.state(['disabled']) # Initially disabled

        self.btn_export = ttk.Button(self, text="Export CSV", command=self.callbacks.get('export'))
        self.btn_export.pack(side=tk.LEFT, padx=5)
        
        self.status_lbl = ttk.Label(self, text="Status: Ready")
        self.status_lbl.pack(side=tk.RIGHT, padx=5)

    def set_scanning_state(self, is_scanning):
        if is_scanning:
            self.btn_scan.state(['disabled'])
            self.btn_stop.state(['!disabled'])
            self.status_lbl.config(text="Status: Scanning...", foreground="blue")
        else:
            self.btn_scan.state(['!disabled'])
            self.btn_stop.state(['disabled'])
            self.status_lbl.config(text="Status: IDLE", foreground="black")

    def update_status(self, msg):
        self.status_lbl.config(text=f"Status: {msg}")
