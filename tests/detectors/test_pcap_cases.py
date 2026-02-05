
import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock
from scapy.all import wrpcap, RadioTap, Dot11, Dot11Beacon, Dot11Elt
from sensor.replay.pcap_reader import PcapStream
from common.detection.pipeline import DetectionPipeline
from controller.detection.detectors.policy import PolicyDetector

# --- Helper: Generate Synthetic PCAP ---
def generate_open_net_pcap(path: Path):
    """Create a PCAP with Open Network beacons."""
    pkts = []
    # Beacon 1: Open Network "OpenCafe"
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
    beacon = Dot11Beacon(cap="ESS") # No Privacy bit
    essid = Dot11Elt(ID="SSID", info="OpenCafe", len=8)
    pkt = RadioTap() / dot11 / beacon / essid
    pkts.append(pkt)
    
    wrpcap(str(path), pkts)

def generate_secure_net_pcap(path: Path):
    """Create a PCAP with Secure Network beacons."""
    pkts = []
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="AA:BB:CC:DD:EE:FF", addr3="AA:BB:CC:DD:EE:FF")
    beacon = Dot11Beacon(cap="ESS+privacy") # Privacy bit set
    essid = Dot11Elt(ID="SSID", info="SecureCorp", len=10)
    pkt = RadioTap() / dot11 / beacon / essid
    pkts.append(pkt)
    
    wrpcap(str(path), pkts)

# --- Tests ---

def test_pcap_regression_open_net(tmp_path):
    """Regression: Open Network Policy Violation."""
    pcap_file = tmp_path / "open_net.pcap"
    generate_open_net_pcap(pcap_file)
    
    # Setup Pipeline
    pipeline = DetectionPipeline()
    pipeline.register(PolicyDetector())
    
    # Run
    stream = PcapStream(pcap_file).stream()
    findings = pipeline.run(list(stream)) # Materialize generator
    
    # Assert
    assert len(findings) == 1
    assert findings[0].reason_codes[0].code == "SECURITY_DOWNGRADE"
    assert "OpenCafe" in findings[0].evidence_list[0].description

def test_pcap_regression_secure_net(tmp_path):
    """Regression: Secure Network (Should NOT fire)."""
    pcap_file = tmp_path / "secure_net.pcap"
    generate_secure_net_pcap(pcap_file)
    
    pipeline = DetectionPipeline()
    pipeline.register(PolicyDetector())
    
    stream = PcapStream(pcap_file).stream()
    findings = pipeline.run(list(stream))
    
    assert len(findings) == 0
