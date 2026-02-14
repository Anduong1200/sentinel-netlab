"""
Gunicorn configuration for Sentinel NetLab Controller.
Production WSGI server settings.

Usage (Docker):
    gunicorn -c controller/gunicorn_conf.py controller.api_server:app

Usage (Local dev — prefer Flask dev server via sentinel.py --debug):
    python sentinel.py controller --debug
"""

import multiprocessing
import os

# Binding
bind = os.getenv("GUNICORN_BIND", "0.0.0.0:5000")  # nosec B104

# Workers: 2 * CPUs + 1 (capped for containers)
_cpu_count = multiprocessing.cpu_count()
workers = int(os.getenv("GUNICORN_WORKERS", min(_cpu_count * 2 + 1, 9)))
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", 4))

# Timeouts
timeout = 120  # Allow slow DB queries / report generation
graceful_timeout = 30
keepalive = 5

# Logging — stdout/stderr for docker log driver
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# Process
proc_name = "sentinel-controller"
daemon = False

# Preload for faster worker fork (shared memory)
preload_app = True


def on_starting(server):
    """Log startup info."""
    server.log.info(
        "Starting Sentinel Controller (gunicorn) — workers=%d threads=%d",
        workers,
        threads,
    )
