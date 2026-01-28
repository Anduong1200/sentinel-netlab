#!/bin/bash
# Sentinel NetLab Packaging Script
# Prepares the project for distribution/deployment

VERSION="1.0.0"
DIST_DIR="dist/sentinel-netlab-v${VERSION}"
TIMESTAMP=$(date +%Y%m%d)

echo "📦 Packaging Sentinel NetLab v${VERSION}..."

# 1. Cleanup
echo "🧹 Cleaning up temporary files..."
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type d -name ".pytest_cache" -exec rm -rf {} +
rm -f *.log
rm -f data/*.db
rm -rf dist/*

# 2. Create Structure
echo "📂 Creating distribution structure..."
mkdir -p "$DIST_DIR"/{bin,config,logs,data,docs}

# 3. Copy Assets
echo "COPYING: Core modules..."
cp -r sensor "$DIST_DIR/"
cp -r algos "$DIST_DIR/"
cp -r scripts "$DIST_DIR/"
cp -r ops "$DIST_DIR/"
cp requirements.txt "$DIST_DIR/"
cp README.md "$DIST_DIR/"
cp LICENSE "$DIST_DIR/" 2>/dev/null || touch "$DIST_DIR/LICENSE"

echo "COPYING: Documentation..."
cp -r docs/*.md "$DIST_DIR/docs/"
cp docs/killer_qa.json "$DIST_DIR/docs/"

# 4. Create Setup Script
cat <<EOF > "$DIST_DIR/install.sh"
#!/bin/bash
echo "Installing Sentinel NetLab Sensor..."
# System Dependencies
sudo apt-get update && sudo apt-get install -y python3-pip python3-venv tshark wireguard wireless-tools

# Python Env
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Permissions
sudo usermod -aG wireshark \$USER
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Config
echo "Generating config..."
if [ ! -f config/risk_weights.yaml ]; then
    mkdir -p config
    python3 scripts/calibrate_weights.py --demo --validate > /dev/null
    mv calibrated_weights.json config/risk_weights.json
fi

echo "✅ Installation Complete. Run './bin/start_sensor.sh'"
EOF
chmod +x "$DIST_DIR/install.sh"

# 5. Create Runtime Scripts
mkdir -p "$DIST_DIR/bin"
cat <<EOF > "$DIST_DIR/bin/start_sensor.sh"
#!/bin/bash
cd "\$(dirname "\$0")/.."
source venv/bin/activate
export WIFI_SCANNER_INTERFACE=\${1:-wlan0}
exec gunicorn -c sensor/gunicorn_conf.py sensor.api_server:app
EOF
chmod +x "$DIST_DIR/bin/start_sensor.sh"

# 6. Archive
echo "🤐 Compressing..."
cd dist
tar -czf "sentinel-netlab-v${VERSION}.tar.gz" "sentinel-netlab-v${VERSION}"
echo "✅ Build Complete: dist/sentinel-netlab-v${VERSION}.tar.gz"
