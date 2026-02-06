
import os
import subprocess
import sys
import time


def debug_run():
    env = os.environ.copy()
    env.update({
        "ENVIRONMENT": "testing",
        "ALLOW_DEV_TOKENS": "true",
        "REQUIRE_TLS": "false",
        "REQUIRE_HMAC": "false",
        "RATE_LIMIT_TELEMETRY": "200 per minute",
        "RATE_LIMIT_ALERTS": "50 per minute",
        "CONTROLLER_SECRET_KEY": "test-secret-key",
        "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
        "CONTROLLER_DATABASE_URL": "sqlite:///debug_controller.db",
        "CONTROLLER_HOST": "127.0.0.1",
        "CONTROLLER_PORT": "5000",
        "CONTROLLER_DEBUG": "false",
        "PYTHONPATH": os.getcwd()
    })

    print("Starting controller...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "controller.api_server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True
    )

    time.sleep(5)
    if proc.poll() is not None:
        print(f"Controller exited early with code {proc.returncode}")
        print("Output:")
        print(proc.stdout.read())
    else:
        print("Controller is running!")
        proc.terminate()
        try:
            print(proc.stdout.read())
        except:
            pass

if __name__ == "__main__":
    debug_run()
