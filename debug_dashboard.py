
import os
import subprocess
import sys
import time


def debug_dashboard():
    # Use a specific port for debug
    port = "8051"

    env = os.environ.copy()
    env.update({
        "CONTROLLER_URL": "http://127.0.0.1:5000",
        "DASHBOARD_API_TOKEN": "analyst-token",
        "DASHBOARD_HOST": "127.0.0.1",
        "DASHBOARD_PORT": port,
        "DASH_USERNAME": "admin",
        "DASH_PASSWORD": "change-me",
        "PYTHONPATH": os.getcwd()
    })

    print(f"Starting dashboard on port {port}...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "dashboard.app"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True
    )

    time.sleep(10)

    if proc.poll() is not None:
        print(f"Dashboard exited early with code {proc.returncode}")
        print("Output:")
        print(proc.stdout.read())
    else:
        print("Dashboard is running!")
        # Try to curl it?
        import requests
        try:
             r = requests.get(f"http://127.0.0.1:{port}/dashboard/", timeout=2)
             print(f"Health check: {r.status_code}")
        except Exception as e:
             print(f"Health check failed: {e}")

        proc.terminate()
        try:
            print("Cleanup: \n" + proc.stdout.read())
        except Exception: # noqa: S110
            pass

if __name__ == "__main__":
    debug_dashboard()
