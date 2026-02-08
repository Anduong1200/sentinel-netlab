# Trusted Proxy & IP Attribution

## Overview
Sentinel NetLab uses a **Trusted Proxy** model to ensure secure IP attribution and TLS enforcement. The application only accepts `X-Forwarded-*` headers from explicitly trusted infrastructure (Load Balancers, Nginx).

## Configuration

### `TRUSTED_PROXY_CIDRS`
*   **Definition**: A comma-separated list of CIDRs (IPv4/IPv6) that are allowed to define the client's identity.
*   **Production Default**: Empty (Security-by-default). You **MUST** configure this.
*   **Example**: `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`

### How it Works
1.  **Direct Connection**: If a request comes from an IP **NOT** in `TRUSTED_PROXY_CIDRS`:
    *   `X-Forwarded-*` headers are **ignored**.
    *   `request.remote_addr` is the socket IP.
    *   `request.scheme` is `http` (usually).
    *   **Result**: Spoofing attacks fail.

2.  **Trusted Connection**: If a request comes from an IP **IN** `TRUSTED_PROXY_CIDRS`:
    *   `X-Forwarded-Proto` is trusted (sets `request.scheme`).
    *   `X-Forwarded-For` is parsed (sets `request.remote_addr`).
    *   **Trust Depth**: We trust exactly **1 hop** (`x_for=1`) by default, meaning we read the *last* IP in the `X-Forwarded-For` list.

## Nginx Configuration (Reference)
Our Nginx configuration is hardened to prevent header pass-through anomalies:

```nginx
# Sets scheme explicitly (overwrites client header)
proxy_set_header X-Forwarded-Proto $scheme;

# Appends client IP (or trusted LB IP) to list
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

# Sets the immediate peer header (useful for debugging)
proxy_set_header X-Real-IP $remote_addr;
```

## Security Guarantees
1.  **TLS Enforcement**: `require_tls=true` only passes if proper `X-Forwarded-Proto: https` is received from a **trusted** source.
2.  **Rate Limiting**: Uses `request.remote_addr`, which is securely resolved to the original client IP (or the immediate peer if untrusted).
