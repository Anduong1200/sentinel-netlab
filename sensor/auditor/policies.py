from .models import Finding, NetworkInfo


class AuditPolicy:
    """Base class for audit policies."""

    def evaluate(self, network: NetworkInfo) -> Finding | None:
        raise NotImplementedError


class OpenNetworkPolicy(AuditPolicy):
    """Policy to detect open networks."""

    def evaluate(self, network: NetworkInfo) -> Finding | None:
        if network.security.upper() == "OPEN":
            return Finding(
                id="WIFI-001",
                title="Open Network Detected",
                severity="High",
                score=70,
                status="Open",
                description=f"Network '{network.ssid}' has no encryption.",
                evidence=[
                    f"BSSID: {network.bssid}",
                    f"Security: {network.security}",
                ],
                evidence_summary=f"Security: {network.security}",
                remediation="Enable WPA2 or WPA3 encryption.",
                remediation_summary="Enable WPA2/WPA3",
                timeline="Immediate",
            )
        return None


class WEPPolicy(AuditPolicy):
    """Policy to detect WEP networks."""

    def evaluate(self, network: NetworkInfo) -> Finding | None:
        if "WEP" in network.security.upper():
            return Finding(
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
                timeline="Immediate",
            )
        return None
