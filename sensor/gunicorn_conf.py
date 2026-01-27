import multiprocessing

bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
timeout = 120
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = "info"
proc_name = "wifi-scanner"

# Security: Run as non-root user if possible
# user = "wifi-user"
# group = "wifi-group"
