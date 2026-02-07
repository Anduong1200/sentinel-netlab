import gzip
import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import UTC, datetime

import requests

# Configuration
CONTROLLER_URL = "http://localhost:5000/api/v1/telemetry"
SENSOR_ID = "soak-sensor-01"
API_KEY = "test-token"  # Needs to be valid/mocked
HMAC_SECRET = "test-hmac"  # noqa: S105

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("soak_test")


class SoakSensor:
    def __init__(self):
        self.running = True
        self.backlog = []
        self.network_up = True

    def sign(self, method, path, timestamp, sensor_id, encoding, payload):
        parts = [method, path, timestamp, sensor_id, encoding]
        canonical = "\n".join(parts) + "\n"
        h = hmac.new(HMAC_SECRET.encode(), digestmod=hashlib.sha256)
        h.update(canonical.encode())
        h.update(payload)
        return h.hexdigest()

    def send_batch(self, batch_id, items):
        if not self.network_up:
            return False

        payload_str = json.dumps(
            {"sensor_id": SENSOR_ID, "batch_id": batch_id, "items": items}
        )
        payload_bytes = gzip.compress(payload_str.encode())

        timestamp = datetime.now(UTC).isoformat()
        sig = self.sign(
            "POST", "/api/v1/telemetry", timestamp, SENSOR_ID, "gzip", payload_bytes
        )

        try:
            resp = requests.post(
                CONTROLLER_URL,
                data=payload_bytes,
                headers={
                    "Content-Encoding": "gzip",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {API_KEY}",
                    "X-Timestamp": timestamp,
                    "X-Sensor-ID": SENSOR_ID,
                    "X-Signature": sig,
                },
                timeout=2,
            )
            return resp.status_code == 202 or resp.status_code == 200
        except Exception:
            return False

    def run(self):
        seq = 0
        while self.running:
            seq += 1
            batch_id = f"{SENSOR_ID}:{seq}"
            items = [{"id": seq, "ts": time.time()}]

            # Try send
            if not self.send_batch(batch_id, items):
                logger.warning(f"Failed to send {batch_id}, adding to backlog")
                self.backlog.append((batch_id, items))
            else:
                logger.info(f"Sent {batch_id}")

            # Dictionary Attack / Drain Backlog
            if self.network_up and self.backlog:
                # Drain one
                b_id, b_items = self.backlog[0]
                if self.send_batch(b_id, b_items):
                    logger.info(f"Drained backlog {b_id}")
                    self.backlog.pop(0)

            time.sleep(0.1)


def main():
    sensor = SoakSensor()
    t = threading.Thread(target=sensor.run)
    t.start()

    # 1. Normal Op (5s)
    time.sleep(5)

    # 2. Cut Network (5s)
    logger.info("CUTTING NETWORK")
    sensor.network_up = False
    time.sleep(5)

    # 3. Restore
    logger.info("RESTORING NETWORK")
    sensor.network_up = True
    time.sleep(5)

    sensor.running = False
    t.join()

    logger.info(f"Final Backlog Size: {len(sensor.backlog)}")
    if len(sensor.backlog) == 0:
        print("PASS: Backlog drained")
    else:
        print("FAIL: Backlog remaining")


if __name__ == "__main__":
    main()
