# Security Policy

## Supported Versions

| Version | Supported |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please send an e-mail to anduong1200@gmail.com based on the project maintainer.

## Important Security Notes

1. **Privileges**: The sensor requires `root` privileges (or `CAP_NET_RAW`/`CAP_NET_ADMIN`) to toggle monitor mode.
   - **Recommendation**: Do not expose the API port (5000) to the public internet. Use an SSH tunnel or VPN.
2. **API Key**: Always change the default API key in `.env`.
3. **Data**: Captured PCAP files may contain sensitive metadata. Ensure strictly controlled access to the VM.
