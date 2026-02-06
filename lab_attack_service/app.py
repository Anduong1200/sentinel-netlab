#!/usr/bin/env python3
"""
Sentinel NetLab - Lab Attack Service API
Isolated service for performing active wireless attacks in a controlled lab environment.
"""

import logging
import os

from attacks import AttackEngine, LabSafetyError
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
limiter = Limiter(key_func=get_remote_address, app=app)

# Configuration
# Configuration
from common.security.secrets import require_secret  # noqa: E402

env = os.getenv("ENVIRONMENT", "lab").lower()

API_KEY = require_secret(
    "Lab API Key",
    "LAB_API_KEY",
    min_len=16,
    allow_dev_autogen=True, # Allowed in Lab/Dev
    env=env
)
INTERFACE = os.environ.get("WIFI_INTERFACE", "wlan0")
LAB_MODE = os.environ.get("SENTINEL_LAB_MODE", "false").lower() == "true"

if not LAB_MODE:
    logger.warning(
        "SENTINEL_LAB_MODE is not true. Attacks will likely fail safety checks."
    )

# Initialize Engine
engine = AttackEngine(interface=INTERFACE)


@app.before_request
def check_auth():
    """Simple API key authentication"""
    if request.endpoint not in ["health"]:
        api_key = request.headers.get("X-API-Key")
        if api_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "lab_attack_service",
            "lab_mode": LAB_MODE,
            "interface": INTERFACE,
        }
    )


@app.route("/attack/deauth", methods=["POST"])
@limiter.limit("5 per minute")
def attack_deauth():
    """Perform Deauthentication Attack"""
    try:
        data = request.get_json()
        target_bssid = data.get("bssid")
        client_mac = data.get("client", "FF:FF:FF:FF:FF:FF")
        count = int(data.get("count", 10))

        if not target_bssid:
            return jsonify({"error": "Missing target_bssid"}), 400

        success = engine.deauth(target_bssid, client_mac, count)
        if success:
            return jsonify(
                {"status": "success", "message": f"Deauth sent to {target_bssid}"}
            )
        return jsonify({"error": "Attack failed"}), 500

    except LabSafetyError as e:
        return jsonify({"error": f"Safety Violation: {str(e)}"}), 403
    except Exception as e:
        logger.error(f"Deauth error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/attack/fakeap", methods=["POST"])
@limiter.limit("5 per minute")
def attack_fakeap():
    """Perform Fake AP Attack"""
    try:
        data = request.get_json()
        ssids = data.get("ssids", [])
        count = int(data.get("count", 100))

        if not ssids:
            return jsonify({"error": "Missing ssids list"}), 400

        success = engine.beacon_flood(ssids, count)
        if success:
            return jsonify(
                {
                    "status": "success",
                    "message": f"Beacon flood sent ({len(ssids)} SSIDs)",
                }
            )
        return jsonify({"error": "Attack failed"}), 500

    except LabSafetyError as e:
        return jsonify({"error": f"Safety Violation: {str(e)}"}), 403
    except Exception as e:
        logger.error(f"FakeAP error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"), port=5001
    )  # Dedicated port for lab service
