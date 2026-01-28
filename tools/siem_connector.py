#!/usr/bin/env python3
"""
Sentinel NetLab - SIEM Connector
Forward alerts from Controller/Sensor to Elasticsearch or Splunk.
"""

import os
import time
import json
import logging
import argparse
import requests
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] SIEM: %(message)s'
)
logger = logging.getLogger(__name__)

class ElasticConnector:
    """Forward events to Elasticsearch"""
    
    def __init__(self, url: str, index: str, api_key: str = None):
        self.url = url
        self.index = index
        self.headers = {'Content-Type': 'application/json'}
        if api_key:
            self.headers['Authorization'] = f'ApiKey {api_key}'

    def send(self, event: Dict[str, Any]):
        """Send single event"""
        try:
            target = f"{self.url}/{self.index}/_doc"
            # Add timestamp if missing
            if '@timestamp' not in event:
                event['@timestamp'] = event.get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%SZ'))
                
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
        self.headers = {'Authorization': f'Splunk {token}'}

    def send(self, event: Dict[str, Any]):
        """Send single event"""
        try:
            payload = {
                'event': event,
                'sourcetype': 'sentinel:alert',
                'time': time.time()
            }
            resp = requests.post(self.url, json=payload, headers=self.headers, timeout=5)
            if resp.status_code != 200:
                logger.error(f"Splunk send failed: {resp.status_code} {resp.text}")
            else:
                logger.debug("Event sent to Splunk")
        except Exception as e:
            logger.error(f"Splunk error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Sentinel NetLab SIEM Connector')
    parser.add_argument('--source', required=True, help='Source API URL (e.g., http://localhost:5000/api/v1/alerts)')
    parser.add_argument('--target', required=True, choices=['elastic', 'splunk'], help='Target SIEM type')
    parser.add_argument('--url', required=True, help='SIEM URL')
    parser.add_argument('--token', help='Auth token/key')
    parser.add_argument('--index', default='sentinel-alerts', help='Elastic index name')
    parser.add_argument('--interval', type=int, default=30, help='Poll interval seconds')
    
    args = parser.parse_args()
    
    # Setup connector
    connector = None
    if args.target == 'elastic':
        connector = ElasticConnector(args.url, args.index, args.token)
    elif args.target == 'splunk':
        connector = SplunkConnector(args.url, args.token)
        
    logger.info(f"Starting SIEM Connector: {args.source} -> {args.target}")
    
    # Polling loop
    last_poll = time.time()
    seen_ids = set()
    
    while True:
        try:
            # Poll source for new alerts
            # In a real scenario, this would track last_seen_id or timestamp
            resp = requests.get(args.source, timeout=10)
            if resp.status_code == 200:
                alerts = resp.json()
                # Assuming list of dicts or dict with 'items'
                items = alerts if isinstance(alerts, list) else alerts.get('items', [])
                
                count = 0
                for alert in items:
                    alert_id = alert.get('id') or str(alert) # simplistic dedupe
                    if alert_id not in seen_ids:
                        connector.send(alert)
                        seen_ids.add(alert_id)
                        count += 1
                        
                        # Cleanup seen_ids to prevent memory leak
                        if len(seen_ids) > 10000:
                            seen_ids.clear()
                            
                if count > 0:
                    logger.info(f"Forwarded {count} new alerts")
            else:
                logger.warning(f"Source poll failed: {resp.status_code}")
                
        except Exception as e:
            logger.error(f"Loop error: {e}")
            
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
