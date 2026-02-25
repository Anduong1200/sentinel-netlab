import shutil
from pathlib import Path


def cleanup_project():
    print("🧹 Starting Project Cleanup for Operation...")

    # Base directory (current script is in scripts/, so go up one level)
    root = Path(__file__).resolve().parent.parent
    print(f"📂 Project Root: {root}")

    # 1. Define Operational Directories
    op_dirs = [
        "data",  # For SQLite database (wifi_scanner.db)
        "logs",  # For application logs
        "captures",  # For PCAP files
        "config",  # For configuration files
        "artifacts",  # For defense artifacts
        "docs",  # Documentation
        "tests",  # Test scripts
        "scripts",  # Helper scripts
        "scripts",  # Helper scripts
        "ops",  # Operations/Docker files
        "algos",  # Algorithms
        "sensor",  # Sensor source code
        "controller",  # Controller source code
    ]

    # 2. Create Directories
    for d in op_dirs:
        path = root / d
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"✅ Created directory: {d}/")
            except Exception as e:
                print(f"❌ Failed to create {d}: {e}")
        else:
            print(f"   Directory exists: {d}/")

    # 3. Clean up Temporary Files
    patterns = [
        "__pycache__",
        "*.pyc",
        "*.pyo",
        "*.pyd",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".coverage",
        ".tox",
        ".venv",
        "*.egg-info",
        "*.log",  # Maybe keep logs? User said cleanup. Let's keep logs in logs/ but del elsewhere.
        "*.tmp",
        "bandit_output*.txt",
        "integration_output*.txt",
        "unit_test_output*.txt",
        "bluetooth_log.json",
        "file_list.txt",
        ".dos_state.json",
        "test_sentinel.db",
        ".env",
        ".DS_Store",
    ]

    print("\n🗑️ Removing temporary files...")
    for pattern in patterns:
        for path in root.rglob(pattern):
            # Skip if specified in specific operational dirs if needed, but usually safe to delete cache
            if "logs" in str(path) and path.suffix == ".log":
                continue

            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                print(f"   Removed: {path.relative_to(root)}")
            except Exception as e:
                print(f"⚠️ Failed to remove {path}: {e}")

    # 4. Check/Move Configuration
    # If config.json is in root, move to config/ or sensor/
    # For now, sensor expects config in its dir or passed via args.
    # We will just ensure config.example.json exists in config/

    config_example = root / "config" / "config.example.json"
    if not config_example.exists():
        example_content = """{
    "interface": "wlan0",
    "engine": "tshark",
    "api_key": "sentinel-2024",
    "risk_threshold": 70,
    "whitelist": ["My_Home_WiFi"],
    "channels": [1, 6, 11]
}"""
        with open(config_example, "w") as f:
            f.write(example_content)
        print("✅ Created config/config.example.json")

    # 5. Create Ready-to-Run Scripts

    # Windows Run Controller
    run_controller_bat = root / "run_controller.bat"
    if not run_controller_bat.exists():
        with open(run_controller_bat, "w") as f:
            f.write("@echo off\ncd controller\npython scanner_gui.py\npause")
        print("✅ Created run_controller.bat")

    print("\n✨ Project is ready for operation!")
    print("   - Run 'run_controller.bat' to start the GUI (Windows)")
    print("   - On Linux sensor: 'python sensor/sensor_cli.py --api'")


if __name__ == "__main__":
    cleanup_project()
