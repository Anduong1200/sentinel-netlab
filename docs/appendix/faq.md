# Frequently Asked Questions

## Q: Why is my WiFi adapter not showing up?
**A**: Ensure your adapter supports **Monitor Mode** and **Packet Injection**. Check if drivers (e.g., `aircrack-ng` drivers) are installed.

## Q: Can I run this on Windows?
**A**: The **Controller** works on Windows (Docker or Python). The **Sensor** requires Linux network primitives for raw socket capture and is not supported on Windows.

## Q: Why am I getting "Signature Mismatch" errors?
**A**: Ensure the `CONTROLLER_HMAC_SECRET` is identical on both Sensor (env var) and Controller (config). Also check system time synchronization (NTP).
