import os
import shutil
from pathlib import Path

def cleanup_project():
    root = Path("d:/hod_lab")
    
    # 1. Standardize Directory Structure
    dirs = [
        "src/sensor", 
        "src/controller", 
        "docs/artifacts",
        "tests",
        "scripts",
        "config"
    ]
    
    for d in dirs:
        (root / d).mkdir(parents=True, exist_ok=True)
    
    print("✅ Created standard directories")

    # 2. Cleanup __pycache__
    for p in root.rglob("__pycache__"):
        try:
            shutil.rmtree(p)
            print(f"🗑️ Removed {p}")
        except Exception as e:
            print(f"⚠️ Failed to remove {p}: {e}")

    # 3. Consolidate Configs
    # (Move scattered config files to /config if explicitly requested, but for now we keep them near code for simplicity
    # or creates symlinks. Here we just ensure no .tmp files usually)
    
    # 4. Generate .gitignore if missing
    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        with open(gitignore_path, "w") as f:
            f.write("*.pyc\n__pycache__/\n*.db\n*.pcap\n.env\nvenv/\n.idea/\n.vscode/\n")
        print("✅ Created .gitignore")

    print("\nProject cleanup complete. Run 'pip install -r requirements.txt' to update deps.")

if __name__ == "__main__":
    cleanup_project()
