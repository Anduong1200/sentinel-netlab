#!/usr/bin/env python3
"""
Generate Lab Secrets (Safe-by-Default)
--------------------------------------
Checks for existence of .env.lab.
If missing, generates one with strong random keys.
This ensures "Zero Config" start while maintaining security best practices (no hardcoded secrets in repo).
"""
import secrets
import sys
from pathlib import Path

# Secrets to generate
KEYS = {
    "CONTROLLER_SECRET_KEY": 32,
    "CONTROLLER_HMAC_SECRET": 64,
    "POSTGRES_PASSWORD": 24,
    "MINIO_ROOT_PASSWORD": 24,
    "REDIS_PASSWORD": 24,
    "DASHBOARD_API_TOKEN": 32,
    "LAB_API_KEY": 32,
    "DASH_PASSWORD": 16, # Default admin password
}

DEFAULTS = {
    "POSTGRES_USER": "sentinel",
    "POSTGRES_DB": "sentinel",
    "MINIO_ROOT_USER": "minioadmin",
    "DASH_USERNAME": "admin",
    "ENVIRONMENT": "lab",
    "LOG_LEVEL": "INFO",
}

def generate_secret(length: int) -> str:
    return secrets.token_hex(length // 2) # token_hex returns 2 chars per byte

def main():
    script_dir = Path(__file__).parent.resolve()
    env_path = script_dir / ".env.lab"

    if env_path.exists():
        print(f"[{sys.argv[0]}] .env.lab already exists. Skipping generation.")
        return 0

    print(f"[{sys.argv[0]}] Generating new .env.lab with strong secrets...")
    
    with open(env_path, "w") as f:
        f.write("# Sentinel NetLab - Lab Secrets (Auto-generated)\n")
        f.write("# DO NOT COMMIT THIS FILE TO GIT\n\n")
        
        # Write Defaults
        for key, value in DEFAULTS.items():
             f.write(f"{key}={value}\n")
        
        f.write("\n# Auto-generated Secrets\n")
        for key, length in KEYS.items():
            secret_val = generate_secret(length)
            f.write(f"{key}={secret_val}\n")

    print(f"[{sys.argv[0]}] Secrets generated at {env_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
