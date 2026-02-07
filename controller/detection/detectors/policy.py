from typing import Any

from common.detection.evidence import Evidence, Finding
from common.detection.reason_codes import ReasonCodes
from controller.detection.interface import AbstractDetector


class PolicyDetector(AbstractDetector):
    """
    Detects violations of static security policies.
    Example: Open networks, WEP encryption.
    """

    def process(
        self, telemetry: dict[str, Any], context: dict[str, Any] | None = None
    ) -> list[Finding]:
        findings = []

        ssid = telemetry.get("ssid", "")
        bssid = telemetry.get("bssid", "")
        security = telemetry.get("security", "Open")

        # 1. Check for Open Networks
        if security == "Open":
            f = Finding(
                detector_id="policy_open_net",
                entity_key=f"policy|{ssid}|{bssid}",
                confidence_raw=1.0,  # Detection is certain
            )
            f.add_reason(ReasonCodes.SECURITY_DOWNGRADE)
            f.evidence_list.append(
                Evidence(
                    type="configuration",
                    description=ReasonCodes.SECURITY_DOWNGRADE.format(
                        ssid=ssid, security="Open", expected="Encrypted"
                    ),
                    data={"security": "Open"},
                )
            )
            findings.append(f)

        # 2. Check for WEP
        if "WEP" in security.upper():
            f = Finding(
                detector_id="policy_wep_net",
                entity_key=f"policy|{ssid}|{bssid}",
                confidence_raw=1.0,
            )
            f.add_reason(ReasonCodes.SECURITY_DOWNGRADE)
            f.evidence_list.append(
                Evidence(
                    type="configuration",
                    description=ReasonCodes.SECURITY_DOWNGRADE.format(
                        ssid=ssid, security=security, expected="WPA2/3"
                    ),
                    data={"security": security},
                )
            )
            findings.append(f)

        return findings
