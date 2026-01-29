#!/usr/bin/env python3
"""
Sentinel NetLab - SIEM Connector
Forward alerts from Controller/Sensor to Elasticsearch or Splunk.
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] SIEM: %(message)s"
)
logger = logging.getLogger(__name__)


class ElasticConnector:
    """Forward events to Elasticsearch"""

    def __init__(self, url: str, index: str, api_key: str = None):
        self.url = url
        self.index = index
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"

    def send(self, event: dict[str, Any]):
        """Send single event"""
        try:
            target = f"{self.url}/{self.index}/_doc"
            # Add timestamp if missing
            if "@timestamp" not in event:
                event["@timestamp"] = event.get(
                    "timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ")
                )

            resp = requests.post(target, json=event, headers=self.headers, timeout=5)
            if resp.status_code not in [200, 201]:
                logger.error(f"Elastic send failed: {resp.status_code} {resp.text}")
            else:
                logger.debug("Event sent to Elastic")
        except Exception as e:
            logger.error(f"Elastic error: {e}")


class SplunkConnector:
    """Forward events to Splunk HEC"""

    def __init__(self, url: str, token: str):
        self.url = url
        self.headers = {"Authorization": f"Splunk {token}"}

    def send(self, event: dict[str, Any]):
        """Send single event"""
        try:
            payload = {
                "event": event,
                "sourcetype": "sentinel:alert",
                "time": time.time(),
            }
            resp = requests.post(
                self.url, json=payload, headers=self.headers, timeout=5
            )
            if resp.status_code != 200:
                logger.error(f"Splunk send failed: {resp.status_code} {resp.text}")
            else:
                logger.debug("Event sent to Splunk")
        except Exception as e:
            logger.error(f"Splunk error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Sentinel NetLab SIEM Connector")
    parser.add_argument(
        "--source",
        required=True,
        help="Source API URL (e.g., http://localhost:5000/api/v1/alerts)",
    )
    parser.add_argument(
        "--target",
        required=True,
        choices=["elastic", "splunk"],
        help="Target SIEM type",
    )
    parser.add_argument("--url", required=True, help="SIEM URL")
    parser.add_argument("--token", help="Auth token/key")
    parser.add_argument("--index", default="sentinel-alerts", help="Elastic index name")
    parser.add_argument(
        "--interval", type=int, default=30, help="Poll interval seconds"
    )

    args = parser.parse_args()

    # Setup connector
    connector = None
    if args.target == "elastic":
        connector = ElasticConnector(args.url, args.index, args.token)
    elif args.target == "splunk":
        connector = SplunkConnector(args.url, args.token)

    logger.info(f"Starting SIEM Connector: {args.source} -> {args.target}")

    # State file
    state_file = Path("siem_connector_state.json")
    last_timestamp = "1970-01-01T00:00:00"

    # Load state
    if state_file.exists():
        try:
            with open(state_file) as f:
                state = json.load(f)
                last_timestamp = state.get("last_timestamp", last_timestamp)
                logger.info(f"Loaded state: last_timestamp={last_timestamp}")
        except Exception as e:
            logger.error(f"Failed to load state: {e}")

    while True:
        try:
            # Poll source for new alerts
            # Pass last_timestamp to API if supported, else filter client-side
            resp = requests.get(args.source, timeout=10)
            if resp.status_code == 200:
                alerts = resp.json()
                items = (
                    alerts
                    if isinstance(alerts, list)
                    else alerts.get("items", []) or alerts.get("alerts", [])
                )

                # Filter and Sort
                # Assuming alerts have "timestamp" or "created_at"
                new_items = []
                for alert in items:
                    ts = (
                        alert.get("timestamp")
                        or alert.get("created_at")
                        or alert.get("time")
                    )
                    if ts and ts > last_timestamp:
                        new_items.append((ts, alert))

                # Sort by timestamp to process in order
                new_items.sort(key=lambda x: x[0])

                count = 0
                processed_max_ts = last_timestamp

                for ts, alert in new_items:
                    connector.send(alert)
                    count += 1
                    if ts > processed_max_ts:
                        processed_max_ts = ts

                if count > 0:
                    last_timestamp = processed_max_ts
                    logger.info(
                        f"Forwarded {count} new alerts. New cursor: {last_timestamp}"
                    )

                    # Save state
                    try:
                        with open(state_file, "w") as f:
                            json.dump({"last_timestamp": last_timestamp}, f)
                    except Exception as e:
                        logger.error(f"Failed to save state: {e}")

            else:
                logger.warning(f"Source poll failed: {resp.status_code}")

        except Exception as e:
            logger.error(f"Loop error: {e}")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
