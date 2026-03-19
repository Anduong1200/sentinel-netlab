import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from .loader import ChecklistLoader
from .models import SEVERITY_SCORES, Finding, NetworkInfo
from .policies import OpenNetworkPolicy, WEPPolicy

logger = logging.getLogger(__name__)


class SecurityAuditor:
    """Perform security checks on discovered networks"""

    def __init__(self, sensor_id: str, profile: str = "home", rules_dir=None):
        self.sensor_id = sensor_id
        self.profile = profile
        self.findings: list[Finding] = []
        # O(1) lookup set to avoid recreating lists of finding IDs during deduplication
        self._finding_ids: set[str] = set()
        self.networks: list[NetworkInfo] = []
        self.manual_findings: list[Finding] = []
        self.policies = [OpenNetworkPolicy(), WEPPolicy()]

        # Load checklist
        loader = ChecklistLoader(rules_dir=rules_dir)
        self.checklist = loader.load_checklist(profile)
        logger.info(f"Loaded {len(self.checklist)} rules for profile '{profile}'")

    def evaluate_network(self, network: NetworkInfo) -> list[Finding]:
        """Evaluate a network against checklist rules"""
        findings = []

        for rule in self.checklist:
            finding = self._evaluate_rule(rule, network)
            if finding:
                findings.append(finding)

        return findings

    def _check_conditions(self, detection: str, network: NetworkInfo) -> list[str]:
        """Check rule detection string against network capability to return evidence items."""
        evidence_items = []
        if "privacy" in detection:
            is_open = not network.capabilities.get("privacy", True)
            if is_open and "false" in detection:
                evidence_items.append(f"Open network: {network.ssid}")
        if "wps" in detection.lower() and network.wps_enabled:
            evidence_items.append("WPS enabled in beacon")
        if "TKIP" in detection:
            pairwise = network.rsn_info.get("pairwise", [])
            if "TKIP" in str(pairwise):
                evidence_items.append(f"TKIP cipher: {pairwise}")
        if "ssid ==" in detection and (not network.ssid or network.ssid == ""):
            if "null" in detection or "''" in detection:
                evidence_items.append("Hidden SSID broadcast")
        return evidence_items

    def _create_finding(
        self, rule: dict, network: NetworkInfo, evidence_items: list[str]
    ) -> Finding:
        """Create a Finding object from rule and evidence."""
        rule_id = rule.get("id", "UNKNOWN")
        severity = rule.get("severity", "Medium")
        if isinstance(rule.get("severity_map"), dict):
            severity = rule["severity_map"].get(network.security.lower(), "Medium")

        score = rule.get("score", SEVERITY_SCORES.get(severity, 40))
        if isinstance(rule.get("score_map"), dict):
            score = rule["score_map"].get(severity, 40)

        return Finding(
            id=rule_id,
            title=rule.get("title", rule_id),
            severity=severity,
            score=score,
            status="Open",
            description=rule.get("description", ""),
            evidence_summary="; ".join(evidence_items),
            evidence=evidence_items,
            remediation=rule.get("remediation_text", ""),
            remediation_summary=rule.get("remediation_text", "")[:80],
            remediation_commands=rule.get("remediation_commands", []),
            timeline=rule.get("recommended_timeline", ""),
            references=[
                {"title": ref, "url": ref if ref.startswith("http") else "#"}
                for ref in rule.get("references", [])
            ],
        )

    def _evaluate_rule(self, rule: dict, network: NetworkInfo) -> Finding | None:
        """Evaluate single rule against network"""
        detection = rule.get("detection_rule", "")

        # Skip manual rules
        if detection == "manual":
            return None

        evidence_items = self._check_conditions(detection, network)
        if evidence_items:
            return self._create_finding(rule, network, evidence_items)

        return None

    def audit_network(self, network: NetworkInfo):
        """Run all checks on a network"""
        self.networks.append(network)

        # Evaluate against checklist
        network_findings = self.evaluate_network(network)
        for finding in network_findings:
            self.findings.append(finding)
            self._finding_ids.add(finding.id)
            logger.warning(
                f"[{finding.severity}] {finding.title}: {finding.evidence_summary}"
            )

        # Legacy built-in checks
        legacy_findings = self._run_legacy_checks(network)
        if legacy_findings:
            for finding in legacy_findings:
                # Avoid duplicates
                if finding.id not in self._finding_ids:
                    self.findings.append(finding)
                    self._finding_ids.add(finding.id)

    def _run_legacy_checks(self, network: NetworkInfo) -> list[Finding]:
        """Built-in checks for backward compatibility"""
        findings = []
        for policy in self.policies:
            finding = policy.evaluate(network)
            if finding:
                findings.append(finding)
        return findings

    def add_manual_finding(self, finding: Finding):
        """Add manually-observed finding (e.g., from admin UI screenshot)"""
        self.manual_findings.append(finding)
        self.findings.append(finding)
        self._finding_ids.add(finding.id)

    def generate_report_data(self, duration_sec: float) -> dict[str, Any]:
        """Generate report data structure for template rendering"""
        # Sort findings by severity
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                severity_order.index(f.severity) if f.severity in severity_order else 99
            ),
        )

        # Count by severity
        counts = {s.lower(): 0 for s in severity_order}
        for f in self.findings:
            key = f.severity.lower()
            if key in counts:
                counts[key] += 1

        return {
            "report": {
                "title": f"Sentinel NetLab Wi-Fi Audit: {self.profile.upper()} — {datetime.now(UTC).strftime('%Y-%m-%d')}",
                "id": f"SN-{datetime.now(UTC).strftime('%Y%m%d')}-{len(self.findings):03d}",
                "date": datetime.now(UTC).strftime("%Y-%m-%d"),
                "sensor_id": self.sensor_id,
                "author": "Sentinel NetLab",
                "exec_summary": self._generate_exec_summary(counts),
            },
            "summary": {
                "counts": counts,
                "networks_scanned": len(self.networks),
                "duration_sec": duration_sec,
            },
            "findings": [asdict(f) for f in sorted_findings],
            "actions": self._generate_action_plan(sorted_findings),
            "appendix": {"telemetry_file": None, "pcap_files": [], "screenshots": []},
        }

    def _generate_exec_summary(self, counts: dict[str, int]) -> str:
        """Generate executive summary text"""
        total = sum(counts.values())
        if total == 0:
            return "No security issues detected. Network configuration appears secure."

        parts = []
        if counts.get("critical", 0) > 0:
            parts.append(f"{counts['critical']} critical")
        if counts.get("high", 0) > 0:
            parts.append(f"{counts['high']} high")
        if counts.get("medium", 0) > 0:
            parts.append(f"{counts['medium']} medium")
        if counts.get("low", 0) > 0:
            parts.append(f"{counts['low']} low")

        return f"Phát hiện {total} vấn đề bảo mật: {', '.join(parts)}. Xem chi tiết bên dưới."

    def _generate_action_plan(self, findings: list[Finding]) -> list[dict]:
        """Generate prioritized action plan"""
        actions = []
        seen_titles = set()

        for f in findings:
            if f.title in seen_titles:
                continue
            seen_titles.add(f.title)

            due = "TBD"
            if f.timeline == "Immediate":
                due = datetime.now(UTC).strftime("%Y-%m-%d")
            elif f.timeline == "24-72h":
                due = "Within 3 days"
            elif f.timeline == "1-4 weeks":
                due = "Within 4 weeks"

            actions.append(
                {
                    "task": f.remediation_summary or f.title,
                    "owner": "IT Team",
                    "due": due,
                    "priority": f.severity,
                }
            )

        return actions[:10]  # Top 10 actions


def scan_mock_networks() -> list[NetworkInfo]:
    """Generate mock networks for testing"""
    return [
        NetworkInfo(
            bssid="AA:BB:CC:11:22:33",
            ssid="SecureNet",
            channel=6,
            rssi_dbm=-45,
            security="WPA2",
            pmf_enabled=True,
            vendor_oui="AA:BB:CC",
            capabilities={"privacy": True, "pmf": True},
        ),
        NetworkInfo(
            bssid="AA:BB:CC:44:55:66",
            ssid="OpenCafe",
            channel=1,
            rssi_dbm=-65,
            security="Open",
            vendor_oui="AA:BB:CC",
            capabilities={"privacy": False},
        ),
        NetworkInfo(
            bssid="AA:BB:CC:77:88:99",
            ssid="OldRouter",
            channel=11,
            rssi_dbm=-70,
            security="WEP",
            vendor_oui="AA:BB:CC",
            capabilities={"privacy": True},
        ),
        NetworkInfo(
            bssid="AA:BB:CC:AA:BB:CC",
            ssid="HomeWiFi",
            channel=6,
            rssi_dbm=-50,
            security="WPA2",
            wps_enabled=True,
            vendor_oui="AA:BB:CC",
            capabilities={"privacy": True, "wps": True},
        ),
        NetworkInfo(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid=None,
            channel=44,
            rssi_dbm=-60,
            security="WPA2",
            hidden=True,
            vendor_oui="AA:BB:CC",
            capabilities={"privacy": True, "hidden_ssid": True},
        ),
        NetworkInfo(
            bssid="11:22:33:44:55:66",
            ssid="FREE_WIFI",
            channel=1,
            rssi_dbm=-40,
            security="Open",
            vendor_oui="11:22:33",
            capabilities={"privacy": False},
        ),
    ]
