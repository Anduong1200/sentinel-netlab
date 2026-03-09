#!/bin/bash
# scripts/build/build_pi_image.sh
#
# This script automates the creation of a Raspberry Pi .img file
# pre-configured with the Sentinel NetLab Sensor.
# It requires `pi-gen` or a similar tool to be installed and configured.

echo "Starting Raspberry Pi Image Build for Sentinel NetLab..."

if [ ! -f "/usr/bin/docker" ]; then
    echo "Docker is required to build the image (e.g., using pi-gen in Docker)."
fi

export IMG_NAME="sentinel-netlab-sensor"
export PI_GEN_DIR="/tmp/pi-gen"

echo "Step 1: Cloning pi-gen..."
if [ ! -d "$PI_GEN_DIR" ]; then
    echo "git clone https://github.com/RPi-Distro/pi-gen.git $PI_GEN_DIR"
fi

echo "Step 2: Configuring custom build stages for Sentinel NetLab..."
# A real implementation would copy specific stage definitions into pi-gen here
# to install docker, clone this repo, and setup systemd services.

echo "Step 3: Building the image (this will take a long time)..."
# cd "$PI_GEN_DIR" && ./build-docker.sh

echo "Done. Image will be available in ${PI_GEN_DIR}/deploy/"
echo "NOTE: This is a placeholder script for automated Pi image building."
