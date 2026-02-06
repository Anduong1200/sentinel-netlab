
import asyncio
import os
import random
import statistics
import time
import uuid
from datetime import datetime

try:
    import httpx
except ImportError:
    print("Please install httpx: pip install httpx")
    exit(1)

# CONFIG
BASE_URL = os.getenv("CONTROLLER_URL", "http://localhost:5000")
NUM_SENSORS = int(os.getenv("NUM_SENSORS", "50"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
DURATION = int(os.getenv("DURATION", "10")) # Seconds

# Token (In a real test, we would generate/provision tokens, but for dev we might use a known one or mock)
# For this script to work without auth bypass, we need valid tokens.
# Assuming 'dev-token' or similar if Auth is disabled or mocked.
# Or we can rely on the fact that we might have a global test token.
AUTH_TOKEN = os.getenv("SENSOR_TOKEN", "mock-token")
SENSOR_HMAC_SECRET = os.getenv("SENSOR_SECRET", "dev-secret")

async def sensor_worker(sensor_id: str, results: list):
    """Simulates a single sensor sending batches."""
    async with httpx.AsyncClient() as client:
        end_time = time.time() + DURATION

        while time.time() < end_time:
            # Generate Batch
            batch_id = uuid.uuid4().hex
            items = []
            for _ in range(BATCH_SIZE):
                items.append({
                    "bssid": f"00:11:22:33:44:{random.randint(10, 99)}",
                    "ssid": f"TestNet-{random.randint(1,100)}",
                    "timestamp": datetime.now().isoformat(),
                    "rssi_dbm": random.randint(-90, -30),
                    "channel": random.choice([1, 6, 11]),
                    "security": "WPA2"
                })

            payload = {
                "sensor_id": sensor_id,
                "batch_id": batch_id,
                "items": items
            }

            # Send
            start_req = time.time()
            try:
                # Note: Real implementation needs HMAC header if require_signed is on.
                # Use X-Sensor-Token if simple auth.
                headers = {"X-Sensor-Token": AUTH_TOKEN}

                resp = await client.post(
                    f"{BASE_URL}/api/v1/telemetry",
                    json=payload,
                    headers=headers,
                    timeout=5.0
                )
                latency = (time.time() - start_req) * 1000 # ms

                results.append({
                    "status": resp.status_code,
                    "latency": latency,
                    "items": BATCH_SIZE
                })

                # Sleep briefly to avoid total DOS (simulate real interval?)
                # await asyncio.sleep(0.1)

            except Exception:
                results.append({
                    "status": "error",
                    "latency": 0,
                    "items": 0
                })
                # print(f"Error: {e}")

async def run_load_test():
    print("=== Sentinel NetLab Load Test ===")
    print(f"Target: {BASE_URL}")
    print(f"Sensors: {NUM_SENSORS}")
    print(f"Duration: {DURATION}s")

    results = []
    tasks = []

    start_time = time.time()

    for i in range(NUM_SENSORS):
        sid = f"bench-sensor-{i}"
        tasks.append(sensor_worker(sid, results))

    await asyncio.gather(*tasks)

    total_time = time.time() - start_time

    # Analysis
    total_reqs = len(results)
    success_reqs = len([r for r in results if r['status'] == 202])
    error_reqs = len([r for r in results if r['status'] in ["error", 500, 503]])
    backpressure_reqs = len([r for r in results if r['status'] == 503])

    total_items = sum([r['items'] for r in results if r['status'] == 202])
    latencies = [r['latency'] for r in results if isinstance(r['status'], int) and r['status'] < 500]

    print("\n=== Results ===")
    print(f"Total Requests: {total_reqs}")
    print(f"Successful:     {success_reqs}")
    print(f"Errors:         {error_reqs} (Backpressure: {backpressure_reqs})")
    print(f"Total Items:    {total_items}")
    print(f"Throughput:     {total_reqs / total_time:.2f} req/sec")
    print(f"Item Rate:      {total_items / total_time:.2f} items/sec")

    if latencies:
        print(f"Latency P50:    {statistics.median(latencies):.2f} ms")
        try:
            print(f"Latency P95:    {statistics.quantiles(latencies, n=20)[18]:.2f} ms") # approx P95
        except:
             pass

if __name__ == "__main__":
    asyncio.run(run_load_test())
