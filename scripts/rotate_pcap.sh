#!/bin/bash
# PCAP Rotation & Archive Script
# Usage: ./rotate_pcap.sh [retention_count]

RETENTION=${1:-30}
PCAP_DIR="/opt/sentinel-netlab/data/captures"
ARCHIVE_DIR="/opt/sentinel-netlab/data/archive"
LOG_FILE="/var/log/wifi-scanner/rotation.log"

timestamp=$(date +%Y%m%d_%H%M%S)

# Ensure dirs exist
mkdir -p "$PCAP_DIR"
mkdir -p "$ARCHIVE_DIR"

log() {
    echo "[$timestamp] $1" >> "$LOG_FILE"
}

# 1. Compress existing PCAPs that aren't compressed and NOT in use
find "$PCAP_DIR" -maxdepth 1 -name "*.pcap" -mmin +2 | while read -r pcap_file; do
    # Check if file is open by any process (e.g. tshark)
    if lsof "$pcap_file" >/dev/null 2>&1; then
        log "Skipping locked file: $pcap_file"
        continue
    fi
    
    # Compress safely
    gzip "$pcap_file" && log "Compressed: $pcap_file"
done

# 2. Rotate (Delete oldest files exceeding retention)
count=$(ls -1 "$PCAP_DIR"/*.gz 2>/dev/null | wc -l)

if [ "$count" -gt "$RETENTION" ]; then
    to_remove=$(($count - $RETENTION))
    log "Rotating $to_remove old capture files..."
    
    ls -1t "$PCAP_DIR"/*.gz | tail -n "$to_remove" | while read -r file; do
        # Option: Move to archive instead of delete
        # mv "$file" "$ARCHIVE_DIR/"
        rm "$file"
        log "Deleted $file"
    done
else
    log "Retention check: $count/$RETENTION files (OK)"
fi

# 3. Optional: S3 Sync (Uncomment to enable)
# aws s3 sync "$ARCHIVE_DIR" s3://my-wifi-bucket/ --delete
