#!/usr/bin/env python3
"""
Sentinel NetLab - Annotated PCAP Generator
Creates sample PCAP files with embedded annotations for ML training.

This tool generates synthetic 802.11 frames for testing and creates
a dataset manifest linking frames to labels.
"""

import os
import json
import time
import random
import struct
import logging
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# PCAP STRUCTURES
# =============================================================================

PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHIIII',
    0xa1b2c3d4,  # Magic number
    2, 4,        # Version major, minor
    0,           # Thiszone
    0,           # Sigfigs
    65535,       # Snaplen
    105          # Network (802.11)
)


def create_pcap_packet_header(ts_sec: int, ts_usec: int, caplen: int, origlen: int) -> bytes:
    return struct.pack('<IIII', ts_sec, ts_usec, caplen, origlen)


def create_radiotap_header() -> bytes:
    """Minimal radiotap header"""
    # Version, pad, length, present flags
    return struct.pack('<BBHI', 0, 0, 8, 0)


def create_beacon_frame(bssid: bytes, ssid: str, channel: int) -> bytes:
    """Create minimal beacon frame"""
    # Frame control (beacon: 0x80 0x00)
    frame_ctrl = struct.pack('<H', 0x0080)
    duration = struct.pack('<H', 0)
    
    # Addresses
    dest = bytes([0xff] * 6)  # Broadcast
    src = bssid
    bss = bssid
    
    # Sequence control
    seq_ctrl = struct.pack('<H', 0)
    
    # Fixed params (8 bytes timestamp + 2 beacon interval + 2 capability)
    fixed = struct.pack('<QHH', int(time.time() * 1000000), 100, 0x0411)
    
    # SSID IE
    ssid_bytes = ssid.encode()[:32]
    ssid_ie = bytes([0, len(ssid_bytes)]) + ssid_bytes
    
    # Supported rates IE (minimal)
    rates_ie = bytes([1, 1, 0x82])
    
    # DS Parameter Set (channel)
    ds_ie = bytes([3, 1, channel])
    
    frame = frame_ctrl + duration + dest + src + bss + seq_ctrl + fixed + ssid_ie + rates_ie + ds_ie
    
    return frame


def create_deauth_frame(bssid: bytes, client: bytes = None) -> bytes:
    """Create deauthentication frame"""
    # Frame control (deauth: 0xc0 0x00)
    frame_ctrl = struct.pack('<H', 0x00c0)
    duration = struct.pack('<H', 0)
    
    dest = client if client else bytes([0xff] * 6)  # Broadcast if no client
    src = bssid
    bss = bssid
    
    seq_ctrl = struct.pack('<H', 0)
    
    # Reason code (3 = deauthenticated because sending STA is leaving)
    reason = struct.pack('<H', 3)
    
    return frame_ctrl + duration + dest + src + bss + seq_ctrl + reason


@dataclass
class AnnotatedFrame:
    """Frame with annotation"""
    frame_number: int
    timestamp: float
    frame_type: str
    bssid: str
    ssid: Optional[str]
    label: str
    label_confidence: float
    notes: str
    raw_offset: int
    raw_length: int


# =============================================================================
# DATASET GENERATOR
# =============================================================================

class AnnotatedPcapGenerator:
    """Generate annotated PCAP files for ML training"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_benign_pcap(self, filename: str, num_frames: int = 100) -> List[AnnotatedFrame]:
        """Generate PCAP with benign beacon frames"""
        filepath = self.output_dir / filename
        annotations = []
        
        # Define some benign APs
        aps = [
            (bytes.fromhex('AABBCC112233'), 'CorpNet', 6),
            (bytes.fromhex('AABBCC445566'), 'GuestWiFi', 1),
            (bytes.fromhex('AABBCC778899'), 'IoTNetwork', 11),
        ]
        
        with open(filepath, 'wb') as f:
            f.write(PCAP_GLOBAL_HEADER)
            offset = len(PCAP_GLOBAL_HEADER)
            
            for i in range(num_frames):
                bssid, ssid, channel = random.choice(aps)
                ts = time.time() + i * 0.1
                
                radiotap = create_radiotap_header()
                frame = create_beacon_frame(bssid, ssid, channel)
                packet = radiotap + frame
                
                header = create_pcap_packet_header(
                    int(ts), int((ts % 1) * 1000000),
                    len(packet), len(packet)
                )
                
                f.write(header + packet)
                
                annotations.append(AnnotatedFrame(
                    frame_number=i + 1,
                    timestamp=ts,
                    frame_type='beacon',
                    bssid=bssid.hex(':'),
                    ssid=ssid,
                    label='benign',
                    label_confidence=1.0,
                    notes='Known AP from inventory',
                    raw_offset=offset,
                    raw_length=len(header) + len(packet)
                ))
                
                offset += len(header) + len(packet)
        
        logger.info(f"Generated {filepath} with {num_frames} benign frames")
        return annotations
    
    def generate_evil_twin_pcap(self, filename: str) -> List[AnnotatedFrame]:
        """Generate PCAP with evil twin attack"""
        filepath = self.output_dir / filename
        annotations = []
        
        legit_bssid = bytes.fromhex('AABBCC112233')
        evil_bssid = bytes.fromhex('DEADBEEF0001')
        ssid = 'CorpNet'
        
        with open(filepath, 'wb') as f:
            f.write(PCAP_GLOBAL_HEADER)
            offset = len(PCAP_GLOBAL_HEADER)
            
            # Mix of legitimate and evil twin frames
            for i in range(50):
                ts = time.time() + i * 0.1
                
                # Legitimate AP
                radiotap = create_radiotap_header()
                frame = create_beacon_frame(legit_bssid, ssid, 6)
                packet = radiotap + frame
                header = create_pcap_packet_header(int(ts), int((ts % 1) * 1000000), len(packet), len(packet))
                f.write(header + packet)
                
                annotations.append(AnnotatedFrame(
                    frame_number=i * 2 + 1,
                    timestamp=ts,
                    frame_type='beacon',
                    bssid=legit_bssid.hex(':'),
                    ssid=ssid,
                    label='benign',
                    label_confidence=1.0,
                    notes='Legitimate AP',
                    raw_offset=offset,
                    raw_length=len(header) + len(packet)
                ))
                offset += len(header) + len(packet)
                
                # Evil twin (after frame 20)
                if i >= 20:
                    ts2 = ts + 0.05
                    frame2 = create_beacon_frame(evil_bssid, ssid, 6)
                    packet2 = radiotap + frame2
                    header2 = create_pcap_packet_header(int(ts2), int((ts2 % 1) * 1000000), len(packet2), len(packet2))
                    f.write(header2 + packet2)
                    
                    annotations.append(AnnotatedFrame(
                        frame_number=i * 2 + 2,
                        timestamp=ts2,
                        frame_type='beacon',
                        bssid=evil_bssid.hex(':'),
                        ssid=ssid,
                        label='evil_twin',
                        label_confidence=0.95,
                        notes='Evil twin: same SSID, different BSSID, stronger signal',
                        raw_offset=offset,
                        raw_length=len(header2) + len(packet2)
                    ))
                    offset += len(header2) + len(packet2)
        
        logger.info(f"Generated {filepath} with evil twin scenario")
        return annotations
    
    def generate_deauth_flood_pcap(self, filename: str) -> List[AnnotatedFrame]:
        """Generate PCAP with deauth flood attack"""
        filepath = self.output_dir / filename
        annotations = []
        
        target_bssid = bytes.fromhex('AABBCC112233')
        
        with open(filepath, 'wb') as f:
            f.write(PCAP_GLOBAL_HEADER)
            offset = len(PCAP_GLOBAL_HEADER)
            
            # Normal traffic first
            for i in range(20):
                ts = time.time() + i * 0.1
                radiotap = create_radiotap_header()
                frame = create_beacon_frame(target_bssid, 'CorpNet', 6)
                packet = radiotap + frame
                header = create_pcap_packet_header(int(ts), int((ts % 1) * 1000000), len(packet), len(packet))
                f.write(header + packet)
                
                annotations.append(AnnotatedFrame(
                    frame_number=i + 1,
                    timestamp=ts,
                    frame_type='beacon',
                    bssid=target_bssid.hex(':'),
                    ssid='CorpNet',
                    label='benign',
                    label_confidence=1.0,
                    notes='Normal beacon before attack',
                    raw_offset=offset,
                    raw_length=len(header) + len(packet)
                ))
                offset += len(header) + len(packet)
            
            # Deauth flood
            base_ts = time.time() + 2
            for i in range(100):
                ts = base_ts + i * 0.02  # 50 frames/sec
                radiotap = create_radiotap_header()
                frame = create_deauth_frame(target_bssid)
                packet = radiotap + frame
                header = create_pcap_packet_header(int(ts), int((ts % 1) * 1000000), len(packet), len(packet))
                f.write(header + packet)
                
                annotations.append(AnnotatedFrame(
                    frame_number=20 + i + 1,
                    timestamp=ts,
                    frame_type='deauth',
                    bssid=target_bssid.hex(':'),
                    ssid=None,
                    label='deauth_flood',
                    label_confidence=0.99,
                    notes=f'Deauth flood attack: {i+1}/100 frames',
                    raw_offset=offset,
                    raw_length=len(header) + len(packet)
                ))
                offset += len(header) + len(packet)
        
        logger.info(f"Generated {filepath} with deauth flood scenario")
        return annotations
    
    def save_manifest(self, filename: str, annotations: List[AnnotatedFrame], pcap_file: str):
        """Save annotation manifest"""
        manifest = {
            'pcap_file': pcap_file,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'total_frames': len(annotations),
            'label_distribution': {},
            'annotations': [asdict(a) for a in annotations]
        }
        
        for a in annotations:
            manifest['label_distribution'][a.label] = manifest['label_distribution'].get(a.label, 0) + 1
        
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"Saved manifest to {filepath}")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate Annotated PCAPs')
    parser.add_argument('--output', default='data/pcap_annotated', help='Output directory')
    
    args = parser.parse_args()
    
    generator = AnnotatedPcapGenerator(args.output)
    
    print("\n" + "=" * 50)
    print("GENERATING ANNOTATED PCAP FILES")
    print("=" * 50)
    
    # Generate each scenario
    annotations1 = generator.generate_benign_pcap('sample_benign.pcap', 100)
    generator.save_manifest('sample_benign_manifest.json', annotations1, 'sample_benign.pcap')
    
    annotations2 = generator.generate_evil_twin_pcap('sample_evil_twin.pcap')
    generator.save_manifest('sample_evil_twin_manifest.json', annotations2, 'sample_evil_twin.pcap')
    
    annotations3 = generator.generate_deauth_flood_pcap('sample_deauth.pcap')
    generator.save_manifest('sample_deauth_manifest.json', annotations3, 'sample_deauth.pcap')
    
    print("\n✅ Generated files:")
    print(f"   - {args.output}/sample_benign.pcap")
    print(f"   - {args.output}/sample_evil_twin.pcap")
    print(f"   - {args.output}/sample_deauth.pcap")
    print("   - Plus JSON manifests with annotations")


if __name__ == '__main__':
    main()
