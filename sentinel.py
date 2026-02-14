#!/usr/bin/env python3
"""
Sentinel NetLab - Unified CLI Entry Point
Routes commands to appropriate sub-modules.
"""

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).parent.absolute()
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))


def main():
    if len(sys.argv) < 2:
        print("Sentinel NetLab - Unified CLI")
        print("\nAvailable commands:")
        print("  monitor     Start the sensor monitor")
        print("  controller  Start the controller API server")
        print("\nUse 'sentinel.py <command> --help' for command-specific options.")
        sys.exit(1)

    command = sys.argv[1]
    remainder = sys.argv[2:]

    if command == "monitor":
        # Pass everything to sensor.cli
        from sensor.cli import main as sensor_main

        sys.argv = [sys.argv[0]] + remainder
        sys.exit(sensor_main())

    elif command == "controller":
        parser = argparse.ArgumentParser(prog="sentinel controller")
        parser.add_argument("--host", default="0.0.0.0", help="Binding host")
        parser.add_argument("--port", type=int, default=5000, help="Binding port")
        parser.add_argument(
            "--debug", action="store_true", help="Enable debug mode (Flask dev server)"
        )
        parser.add_argument(
            "--workers", type=int, default=0, help="Gunicorn workers (0=auto)"
        )

        args = parser.parse_args(remainder)

        if args.debug:
            # Dev mode: Flask built-in server with reloader
            from controller.api_server import app

            print(f"Starting Sentinel Controller (DEBUG) on {args.host}:{args.port}")
            app.run(host=args.host, port=args.port, debug=True)
        else:
            # Production: Gunicorn
            import subprocess

            workers = args.workers or min((os.cpu_count() or 1) * 2 + 1, 9)
            cmd = [
                sys.executable,
                "-m",
                "gunicorn",
                "-c",
                "controller/gunicorn_conf.py",
                "-b",
                f"{args.host}:{args.port}",
                "-w",
                str(workers),
                "controller.api_server:app",
            ]
            print(
                f"Starting Sentinel Controller (gunicorn) on {args.host}:{args.port} workers={workers}"
            )
            sys.exit(subprocess.call(cmd))

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
