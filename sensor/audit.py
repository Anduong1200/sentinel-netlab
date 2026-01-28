#!/usr/bin/env python3
"""
Sentinel NetLab - Security Audit CLI
Perform automated WiFi security assessments with Home/SME profiles.

Usage:
    python audit.py --iface wlan0 --profile home --output report.json
    python audit.py --profile sme --format html --output report.html
"""

import sys
import json
import logging
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, List, Any
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class CheckStatus(str, Enum):
    PASS = "Pass"
    FAIL = "Fail"
    WARN = "Warn"
    SKIP = "Skip"
    OPEN = "Open"


SEVERITY_SCORES = {
    "Critical": 90,
    "High": 70,
    "Medium": 40,
    "Low": 10,
    "Info": 0
}


@dataclass
class Finding:
    """Security finding from audit"""
    id: str
    title: str
    severity: str
    score: int
    status: str
    description: str
    evidence_summary: str = ""
    evidence: List[str] = field(default_factory=list)
    evidence_raw: Optional[str] = None
    remediation: str = ""
    remediation_summary: str = ""
    remediation_commands: List[str] = field(default_factory=list)
    timeline: str = ""
    references: List[Dict[str, str]] = field(default_factory=list)


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
    vendor_oui: Optional[str] = None
    rsn_info: Dict = field(default_factory=dict)
    capabilities: Dict = field(default_factory=dict)


# =============================================================================
# CHECKLIST LOADER
# =============================================================================

class ChecklistLoader:
    """Load and manage audit checklists"""

    def __init__(self, rules_dir: Path = None):
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"
        self.rules_dir = rules_dir

    def load_checklist(self, profile: str) -> List[Dict]:
        """Load checklist for profile (home/sme)"""
        filename = f"audit-{profile}-checklist.json"
        filepath = self.rules_dir / filename

        if not filepath.exists():
            logger.warning(f"Checklist not found: {filepath}")
            return []

        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    def get_profiles(self) -> List[str]:
        """List available profiles"""
        profiles = []
        for f in self.rules_dir.glob("audit-*-checklist.json"):
            match = re.match(r"audit-(.+)-checklist\.json", f.name)
            if match:
                profiles.append(match.group(1))
        return profiles


# =============================================================================
# SECURITY AUDITOR
# =============================================================================

class SecurityAuditor:
    """Perform security checks on discovered networks"""

    def __init__(self, sensor_id: str, profile: str = "home"):
        self.sensor_id = sensor_id
        self.profile = profile
        self.findings: List[Finding] = []
        self.networks: List[NetworkInfo] = []
        self.manual_findings: List[Finding] = []

        # Load checklist
        loader = ChecklistLoader()
        self.checklist = loader.load_checklist(profile)
        logger.info(f"Loaded {len(self.checklist)} rules for profile '{profile}'")

    def evaluate_network(self, network: NetworkInfo) -> List[Finding]:
        """Evaluate a network against checklist rules"""
        findings = []

        for rule in self.checklist:
            finding = self._evaluate_rule(rule, network)
            if finding:
                findings.append(finding)

        return findings

    def _evaluate_rule(self, rule: Dict, network: NetworkInfo) -> Optional[Finding]:
        """Evaluate single rule against network"""
        rule_id = rule.get('id', 'UNKNOWN')
        detection = rule.get('detection_rule', '')

        # Skip manual rules
        if detection == 'manual':
            return None

        triggered = False
        evidence_items = []

        # Encryption check
        if 'privacy' in detection:
            is_open = not network.capabilities.get('privacy', True)
            if is_open and 'false' in detection:
                triggered = True
                evidence_items.append(f"Open network: {network.ssid}")

        # WPS check
        if 'wps' in detection.lower() and network.wps_enabled:
            triggered = True
            evidence_items.append("WPS enabled in beacon")

        # TKIP check
        if 'TKIP' in detection:
            pairwise = network.rsn_info.get('pairwise', [])
            if 'TKIP' in str(pairwise):
                triggered = True
                evidence_items.append(f"TKIP cipher: {pairwise}")

        # Hidden SSID
        if 'ssid ==' in detection and (not network.ssid or network.ssid == ''):
            if 'null' in detection or "''" in detection:
                triggered = True
                evidence_items.append("Hidden SSID broadcast")

        # Duplicate SSID (placeholder - needs multi-network context)
        # This would be handled at a higher level

        if triggered:
            severity = rule.get('severity', 'Medium')
            if isinstance(rule.get('severity_map'), dict):
                # Dynamic severity based on encryption type
                sec_lower = network.security.lower()
                severity = rule['severity_map'].get(sec_lower, 'Medium')

            score = rule.get('score', SEVERITY_SCORES.get(severity, 40))
            if isinstance(rule.get('score_map'), dict):
                score = rule['score_map'].get(severity, 40)

            return Finding(
                id=rule_id,
                title=rule.get('title', rule_id),
                severity=severity,
                score=score,
                status="Open",
                description=rule.get('description', ''),
                evidence_summary='; '.join(evidence_items),
                evidence=evidence_items,
                remediation=rule.get('remediation_text', ''),
                remediation_summary=rule.get('remediation_text', '')[:80],
                remediation_commands=rule.get('remediation_commands', []),
                timeline=rule.get('recommended_timeline', ''),
                references=[
                    {'title': ref, 'url': ref if ref.startswith('http') else '#'}
                    for ref in rule.get('references', [])
                ]
            )

        return None

    def audit_network(self, network: NetworkInfo):
        """Run all checks on a network"""
        self.networks.append(network)

        # Evaluate against checklist
        network_findings = self.evaluate_network(network)
        for finding in network_findings:
            self.findings.append(finding)
            logger.warning(f"[{finding.severity}] {finding.title}: {finding.evidence_summary}")

        # Legacy built-in checks
        legacy_findings = self._run_legacy_checks(network)
        for finding in legacy_findings:
            # Avoid duplicates
            if not any(f.id == finding.id for f in self.findings):
                self.findings.append(finding)

    def _run_legacy_checks(self, network: NetworkInfo) -> List[Finding]:
        """Built-in checks for backward compatibility"""
        findings = []

        # Open network
        if network.security.upper() == 'OPEN':
            findings.append(Finding(
                id="WIFI-001",
                title="Open Network Detected",
                severity="High",
                score=70,
                status="Open",
                description=f"Network '{network.ssid}' has no encryption.",
                evidence=[f"BSSID: {network.bssid}", f"Security: {network.security}"],
                evidence_summary=f"Security: {network.security}",
                remediation="Enable WPA2 or WPA3 encryption.",
                remediation_summary="Enable WPA2/WPA3",
                timeline="Immediate"
            ))

        # WEP network
        if 'WEP' in network.security.upper():
            findings.append(Finding(
                id="WIFI-002",
                title="WEP Encryption Detected",
                severity="Critical",
                score=90,
                status="Open",
                description=f"Network '{network.ssid}' uses WEP, cryptographically broken.",
                evidence=[f"BSSID: {network.bssid}"],
                evidence_summary=f"Security: {network.security}",
                remediation="Upgrade to WPA2 or WPA3 immediately.",
                remediation_summary="Replace WEP with WPA2/WPA3",
                timeline="Immediate"
            ))

        return findings

    def add_manual_finding(self, finding: Finding):
        """Add manually-observed finding (e.g., from admin UI screenshot)"""
        self.manual_findings.append(finding)
        self.findings.append(finding)

    def generate_report_data(self, duration_sec: float) -> Dict[str, Any]:
        """Generate report data structure for template rendering"""
        # Sort findings by severity
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
        )

        # Count by severity
        counts = {s.lower(): 0 for s in severity_order}
        for f in self.findings:
            key = f.severity.lower()
            if key in counts:
                counts[key] += 1

        return {
            "report": {
                "title": f"Sentinel NetLab Wi-Fi Audit: {self.profile.upper()} — {datetime.now().strftime('%Y-%m-%d')}",
                "id": f"SN-{datetime.now().strftime('%Y%m%d')}-{len(self.findings):03d}",
                "date": datetime.now().strftime('%Y-%m-%d'),
                "sensor_id": self.sensor_id,
                "author": "Sentinel NetLab",
                "exec_summary": self._generate_exec_summary(counts)
            },
            "summary": {
                "counts": counts,
                "networks_scanned": len(self.networks),
                "duration_sec": duration_sec
            },
            "findings": [asdict(f) for f in sorted_findings],
            "actions": self._generate_action_plan(sorted_findings),
            "appendix": {
                "telemetry_file": None,
                "pcap_files": [],
                "screenshots": []
            }
        }

    def _generate_exec_summary(self, counts: Dict[str, int]) -> str:
        """Generate executive summary text"""
        total = sum(counts.values())
        if total == 0:
            return "No security issues detected. Network configuration appears secure."

        parts = []
        if counts.get('critical', 0) > 0:
            parts.append(f"{counts['critical']} critical")
        if counts.get('high', 0) > 0:
            parts.append(f"{counts['high']} high")
        if counts.get('medium', 0) > 0:
            parts.append(f"{counts['medium']} medium")
        if counts.get('low', 0) > 0:
            parts.append(f"{counts['low']} low")

        return f"Phát hiện {total} vấn đề bảo mật: {', '.join(parts)}. Xem chi tiết bên dưới."

    def _generate_action_plan(self, findings: List[Finding]) -> List[Dict]:
        """Generate prioritized action plan"""
        actions = []
        seen_titles = set()

        for f in findings:
            if f.title in seen_titles:
                continue
            seen_titles.add(f.title)

            due = "TBD"
            if f.timeline == "Immediate":
                due = datetime.now().strftime('%Y-%m-%d')
            elif f.timeline == "24-72h":
                due = "Within 3 days"
            elif f.timeline == "1-4 weeks":
                due = "Within 4 weeks"

            actions.append({
                "task": f.remediation_summary or f.title,
                "owner": "IT Team",
                "due": due,
                "priority": f.severity
            })

        return actions[:10]  # Top 10 actions


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generate reports in various formats"""

    def __init__(self, templates_dir: Path = None):
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "templates"
        self.templates_dir = templates_dir

    def render_html(self, data: Dict[str, Any]) -> str:
        """Render HTML report using Jinja2"""
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            logger.error("Jinja2 not installed. Run: pip install jinja2")
            return "<html><body><h1>Error: Jinja2 not installed</h1></body></html>"

        env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        template = env.get_template("report_template.html")
        return template.render(**data)

    def render_json(self, data: Dict[str, Any]) -> str:
        """Render JSON report"""
        return json.dumps(data, indent=2, ensure_ascii=False)

    def save_report(self, data: Dict[str, Any], output_path: Path, format: str = "json"):
        """Save report to file"""
        if format == "html":
            content = self.render_html(data)
        else:
            content = self.render_json(data)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"Report saved to {output_path}")


# =============================================================================
# MOCK DATA
# =============================================================================

def scan_mock_networks() -> List[NetworkInfo]:
    """Generate mock networks for testing"""
    return [
        NetworkInfo(
            bssid="AA:BB:CC:11:22:33", ssid="SecureNet", channel=6,
            rssi_dbm=-45, security="WPA2", pmf_enabled=True,
            vendor_oui="AA:BB:CC", capabilities={'privacy': True, 'pmf': True}
        ),
        NetworkInfo(
            bssid="AA:BB:CC:44:55:66", ssid="OpenCafe", channel=1,
            rssi_dbm=-65, security="Open",
            vendor_oui="AA:BB:CC", capabilities={'privacy': False}
        ),
        NetworkInfo(
            bssid="AA:BB:CC:77:88:99", ssid="OldRouter", channel=11,
            rssi_dbm=-70, security="WEP",
            vendor_oui="AA:BB:CC", capabilities={'privacy': True}
        ),
        NetworkInfo(
            bssid="AA:BB:CC:AA:BB:CC", ssid="HomeWiFi", channel=6,
            rssi_dbm=-50, security="WPA2", wps_enabled=True,
            vendor_oui="AA:BB:CC", capabilities={'privacy': True, 'wps': True}
        ),
        NetworkInfo(
            bssid="AA:BB:CC:DD:EE:FF", ssid=None, channel=44,
            rssi_dbm=-60, security="WPA2", hidden=True,
            vendor_oui="AA:BB:CC", capabilities={'privacy': True, 'hidden_ssid': True}
        ),
        NetworkInfo(
            bssid="11:22:33:44:55:66", ssid="FREE_WIFI", channel=1,
            rssi_dbm=-40, security="Open",
            vendor_oui="11:22:33", capabilities={'privacy': False}
        ),
    ]


# =============================================================================
# MAIN
# =============================================================================

def run_audit(args) -> int:
    """Main audit function"""
    start_time = datetime.now(timezone.utc)

    print("\n" + "=" * 60)
    print("🔍 SENTINEL NETLAB SECURITY AUDIT")
    print("=" * 60)
    print(f"Sensor ID: {args.sensor_id}")
    print(f"Interface: {args.iface}")
    print(f"Profile:   {args.profile}")
    print(f"Format:    {args.format}")
    print(f"Started:   {start_time.isoformat()}")
    print("=" * 60 + "\n")

    auditor = SecurityAuditor(args.sensor_id, profile=args.profile)

    # Get networks
    if args.mock:
        logger.info("Using mock network data")
        networks = scan_mock_networks()
    else:
        logger.info(f"Scanning on {args.iface}...")
        # TODO: Implement real scanning with capture_driver
        networks = scan_mock_networks()

    logger.info(f"Found {len(networks)} networks")

    # Run audit
    for network in networks:
        ssid_display = network.ssid or "[Hidden]"
        logger.info(f"Auditing: {ssid_display} ({network.bssid})")
        auditor.audit_network(network)

    # Generate report
    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    report_data = auditor.generate_report_data(duration)

    # Save report
    output_path = Path(args.output)
    generator = ReportGenerator()
    generator.save_report(report_data, output_path, format=args.format)

    # Print summary
    counts = report_data['summary']['counts']
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    print(f"Networks Scanned: {report_data['summary']['networks_scanned']}")
    print(f"Duration:         {duration:.1f} seconds")
    print("\nFindings by Severity:")
    print(f"  CRITICAL: {counts.get('critical', 0)}")
    print(f"  HIGH:     {counts.get('high', 0)}")
    print(f"  MEDIUM:   {counts.get('medium', 0)}")
    print(f"  LOW:      {counts.get('low', 0)}")
    print("=" * 60 + "\n")

    # Return exit code
    if counts.get('critical', 0) > 0:
        return 2
    elif counts.get('high', 0) > 0:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Sentinel NetLab Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mock audit with home profile
  python audit.py --sensor-id test --mock --profile home

  # SME audit with HTML output
  python audit.py --sensor-id pi-01 --profile sme --format html --output report.html

  # Real scan
  python audit.py --sensor-id pi-01 --iface wlan0mon --output audit.json

Profiles:
  home  - Home/SOHO router checks (WPS, encryption, defaults)
  sme   - Small/Medium Enterprise (802.1X, VLAN, RADIUS, compliance)

IMPORTANT: Use only on networks you own or have authorization to assess.
See ETHICS.md for legal guidelines.
        """
    )

    parser.add_argument('--sensor-id', default='audit-cli', help='Sensor identifier')
    parser.add_argument('--iface', default='wlan0', help='WiFi interface')
    parser.add_argument('--output', default='audit_report.json', help='Output file')
    parser.add_argument('--format', choices=['json', 'html'], default='json', help='Output format')
    parser.add_argument('--profile', choices=['home', 'sme'], default='home', help='Audit profile')
    parser.add_argument('--mock', action='store_true', help='Use mock data')

    args = parser.parse_args()

    sys.exit(run_audit(args))


if __name__ == '__main__':
    main()
