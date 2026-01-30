# Sensor Hardening Scope

Sensors are deployed in untrusted physical environments and must be hardened against compromise.

## 1. OS Hardening (Raspberry Pi OS / Linux)
- **User Accounts**: Disable default `pi` user. Use SSH keys only.
- **Firewall**: `ufw` allow outgoing 443, deny incoming (except management SSH on VPN).
- **Updates**: Unattended upgrades enabled for security patches.
- **Disk Encryption**: `dm-crypt` / LUKS for localized storage (journal).

## 2. Application Hardening
- **Least Privilege**: Sensor process runs as non-root user `sentinel`.
- **Capabilities**: Grant specific capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) instead of sudo.
- **Read-Only Root**: Mount root filesystem as read-only (OverlayFS) to prevent persistence.

## 3. Secret Management
- **Env Vars**: Secrets injected at runtime, not stored in config files.
- **No Persistence**: HMAC keys should not be written to disk.
- **Memory**: Python's `gc` cannot guarantee clearing memory, but short-lived processes help.

## 4. Compromise Recovery
If a sensor is physical compromised:
1. **Revoke Token**: Invalidate `sensor-id` token at Controller.
2. **Rotate HMAC**: Rotate the shared HMAC secret (requires updating all sensors).
3. **Re-image**: Do not attempt to clean; re-flash SD card from trusted image.
