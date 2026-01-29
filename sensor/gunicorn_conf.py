"""
Gunicorn configuration for Sentinel NetLab Sensor
Run with: gunicorn -c gunicorn_conf.py api_server:app
"""

import multiprocessing

# Binding
bind = "0.0.0.0:5000"  # nosec B104

# Workers (Formula: 2 * CPUs + 1)
# Workers (Formula: 2 * CPUs + 1)
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gthread"
threads = 4  # Async IO support
timeout = 120  # Extended timeout for scans

# Logging
loglevel = "info"
accesslog = "/var/log/wifi-scanner/access.log"
errorlog = "/var/log/wifi-scanner/error.log"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# Process Naming
proc_name = "wifi-sensor-api"

# Daemon mode (usually controlled by systemd, so False here)
daemon = False

# Environment
raw_env = ["WIFI_SCANNER_INTERFACE=wlan0", "PYTHONUNBUFFERED=TRUE"]


def on_starting(server):
    print("🚀 Starting Sentinel NetLab Sensor API...")
