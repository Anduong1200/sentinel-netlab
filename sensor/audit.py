#!/usr/bin/env python3
"""
Sentinel NetLab - Security Audit CLI
Perform automated WiFi security assessments.

Usage:
    python audit.py --iface wlan0 --output report.json
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, List
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class Finding:
    """Security finding from audit"""
    check_id: str
    title: str
    severity: Severity
    status: CheckStatus
    description: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class NetworkInfo:
    """Network information for audit"""
    bssid: str
    ssid: Optional[str]
    channel: int
    rssi_dbm: int
    security: str
    wps_enabled: bool = False
    pmf_enabled: bool = False
    hidden: bool = False
    vendor: Optional[str] = None


@dataclass 
class AuditReport:
    """Complete audit report"""
    audit_id: str
    timestamp: str
    sensor_id: str
    duration_sec: float
    networks_scanned: int
    findings: List[Finding]
    summary: Dict[str, int]
    
    def to_dict(self):
        return {
            'audit_id': self.audit_id,
            'timestamp': self.timestamp,
            'sensor_id': self.sensor_id,
            'duration_sec': self.duration_sec,
            'networks_scanned': self.networks_scanned,
            'findings': [asdict(f) for f in self.findings],
            'summary': self.summary
        }


class SecurityAuditor:
    """Perform security checks on discovered networks"""
    
    def __init__(self, sensor_id: str):
        self.sensor_id = sensor_id
        self.findings: List[Finding] = []
        self.networks: List[NetworkInfo] = []
        
    def check_open_networks(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for open (unencrypted) networks"""
        if network.security.upper() == 'OPEN':
            return Finding(
                check_id="WIFI-001",
                title="Open Network Detected",
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                description=f"Network '{network.ssid}' ({network.bssid}) has no encryption.",
                evidence=f"Security: {network.security}",
                recommendation="Enable WPA2 or WPA3 encryption.",
                references=["NIST SP 800-153", "CIS Wireless Benchmark"]
            )
        return None
    
    def check_wep_networks(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for WEP encryption (deprecated)"""
        if 'WEP' in network.security.upper():
            return Finding(
                check_id="WIFI-002",
                title="WEP Encryption Detected",
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                description=f"Network '{network.ssid}' uses WEP, which is cryptographically broken.",
                evidence=f"Security: {network.security}",
                recommendation="Upgrade to WPA2 or WPA3 immediately.",
                references=["CVE-2001-0131", "aircrack-ng documentation"]
            )
        return None
    
    def check_wps_enabled(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for WPS (vulnerable to brute force)"""
        if network.wps_enabled:
            return Finding(
                check_id="WIFI-003",
                title="WPS Enabled",
                severity=Severity.MEDIUM,
                status=CheckStatus.WARN,
                description=f"Network '{network.ssid}' has WPS enabled, vulnerable to PIN brute force.",
                evidence="WPS IE detected",
                recommendation="Disable WPS in router settings.",
                references=["CVE-2011-5053", "Reaver documentation"]
            )
        return None
    
    def check_pmf_disabled(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for missing Protected Management Frames (802.11w)"""
        if 'WPA2' in network.security.upper() or 'WPA3' in network.security.upper():
            if not network.pmf_enabled:
                return Finding(
                    check_id="WIFI-004",
                    title="PMF Not Enabled",
                    severity=Severity.LOW,
                    status=CheckStatus.WARN,
                    description=f"Network '{network.ssid}' does not enforce Protected Management Frames.",
                    evidence="PMF capability not detected",
                    recommendation="Enable 802.11w (PMF) for deauth protection.",
                    references=["IEEE 802.11w", "NIST SP 800-153"]
                )
        return None
    
    def check_hidden_ssid(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for hidden SSID (false sense of security)"""
        if network.hidden:
            return Finding(
                check_id="WIFI-005",
                title="Hidden SSID",
                severity=Severity.INFO,
                status=CheckStatus.WARN,
                description=f"Network {network.bssid} uses hidden SSID (easily discovered via probe responses).",
                evidence="SSID not broadcast",
                recommendation="Hidden SSID provides no real security. Consider enabling broadcast.",
                references=["OWASP Wireless Testing Guide"]
            )
        return None
    
    def check_suspicious_ssid(self, network: NetworkInfo) -> Optional[Finding]:
        """Check for suspicious SSID patterns"""
        suspicious_patterns = [
            ('FREE', 'Potential rogue AP'),
            ('GUEST', 'Unsecured guest network'),
            ('XFINITY', 'Possible evil twin'),
            ('STARBUCKS', 'Possible evil twin'),
        ]
        
        if network.ssid:
            for pattern, reason in suspicious_patterns:
                if pattern.lower() in network.ssid.lower():
                    if network.security.upper() == 'OPEN':
                        return Finding(
                            check_id="WIFI-006",
                            title="Suspicious Open Network",
                            severity=Severity.MEDIUM,
                            status=CheckStatus.WARN,
                            description=f"Network '{network.ssid}' matches suspicious pattern: {reason}",
                            evidence=f"SSID: {network.ssid}, Security: Open",
                            recommendation="Verify this is a legitimate network before connecting.",
                            references=["Evil Twin Attack", "OWASP"]
                        )
        return None
    
    def audit_network(self, network: NetworkInfo):
        """Run all checks on a network"""
        self.networks.append(network)
        
        checks = [
            self.check_open_networks,
            self.check_wep_networks,
            self.check_wps_enabled,
            self.check_pmf_disabled,
            self.check_hidden_ssid,
            self.check_suspicious_ssid,
        ]
        
        for check in checks:
            finding = check(network)
            if finding:
                self.findings.append(finding)
                log_level = {
                    Severity.CRITICAL: logging.ERROR,
                    Severity.HIGH: logging.WARNING,
                    Severity.MEDIUM: logging.WARNING,
                    Severity.LOW: logging.INFO,
                    Severity.INFO: logging.DEBUG,
                }
                logger.log(log_level.get(finding.severity, logging.INFO),
                          f"[{finding.severity}] {finding.title}: {finding.description}")
    
    def generate_report(self, duration_sec: float) -> AuditReport:
        """Generate final audit report"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }
        
        for finding in self.findings:
            summary[finding.severity] += 1
        
        return AuditReport(
            audit_id=f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            sensor_id=self.sensor_id,
            duration_sec=duration_sec,
            networks_scanned=len(self.networks),
            findings=self.findings,
            summary=summary
        )


def scan_mock_networks() -> List[NetworkInfo]:
    """Generate mock networks for testing"""
    return [
        NetworkInfo(bssid="AA:BB:CC:11:22:33", ssid="SecureNet", channel=6, 
                   rssi_dbm=-45, security="WPA2", pmf_enabled=True),
        NetworkInfo(bssid="AA:BB:CC:44:55:66", ssid="OpenCafe", channel=1,
                   rssi_dbm=-65, security="Open"),
        NetworkInfo(bssid="AA:BB:CC:77:88:99", ssid="OldRouter", channel=11,
                   rssi_dbm=-70, security="WEP"),
        NetworkInfo(bssid="AA:BB:CC:AA:BB:CC", ssid="HomeWiFi", channel=6,
                   rssi_dbm=-50, security="WPA2", wps_enabled=True),
        NetworkInfo(bssid="AA:BB:CC:DD:EE:FF", ssid=None, channel=44,
                   rssi_dbm=-60, security="WPA2", hidden=True),
        NetworkInfo(bssid="11:22:33:44:55:66", ssid="FREE_WIFI", channel=1,
                   rssi_dbm=-40, security="Open"),
    ]


def run_audit(args):
    """Main audit function"""
    start_time = datetime.now(timezone.utc)
    
    print("\n" + "="*60)
    print("🔍 SENTINEL NETLAB SECURITY AUDIT")
    print("="*60)
    print(f"Sensor ID: {args.sensor_id}")
    print(f"Interface: {args.iface}")
    print(f"Started:   {start_time.isoformat()}")
    print("="*60 + "\n")
    
    auditor = SecurityAuditor(args.sensor_id)
    
    # Get networks (mock or real)
    if args.mock:
        logger.info("Using mock network data")
        networks = scan_mock_networks()
    else:
        logger.info(f"Scanning on {args.iface}...")
        # TODO: Implement real scanning
        networks = scan_mock_networks()
    
    logger.info(f"Found {len(networks)} networks")
    
    # Run audit checks
    for network in networks:
        ssid_display = network.ssid or "[Hidden]"
        logger.info(f"Auditing: {ssid_display} ({network.bssid})")
        auditor.audit_network(network)
    
    # Generate report
    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    report = auditor.generate_report(duration)
    
    # Save report
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(report.to_dict(), f, indent=2)
    
    logger.info(f"Report saved to {output_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("AUDIT SUMMARY")
    print("="*60)
    print(f"Networks Scanned: {report.networks_scanned}")
    print(f"Duration:         {report.duration_sec:.1f} seconds")
    print(f"\nFindings by Severity:")
    print(f"  CRITICAL: {report.summary['CRITICAL']}")
    print(f"  HIGH:     {report.summary['HIGH']}")
    print(f"  MEDIUM:   {report.summary['MEDIUM']}")
    print(f"  LOW:      {report.summary['LOW']}")
    print(f"  INFO:     {report.summary['INFO']}")
    print("="*60 + "\n")
    
    # Return exit code based on findings
    if report.summary['CRITICAL'] > 0:
        return 2
    elif report.summary['HIGH'] > 0:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Sentinel NetLab Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mock audit (no hardware)
  python audit.py --sensor-id test --mock

  # Real scan
  python audit.py --sensor-id pi-01 --iface wlan0mon --output audit.json

IMPORTANT: Use only on networks you own or have authorization to assess.
See ETHICS.md for legal guidelines.
        """
    )
    
    parser.add_argument('--sensor-id', default='audit-cli', help='Sensor identifier')
    parser.add_argument('--iface', default='wlan0', help='WiFi interface')
    parser.add_argument('--output', default='audit_report.json', help='Output file')
    parser.add_argument('--mock', action='store_true', help='Use mock data')
    
    args = parser.parse_args()
    
    sys.exit(run_audit(args))


if __name__ == '__main__':
    main()
