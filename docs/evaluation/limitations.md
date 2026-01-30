# System Limitations

While effective for educational and research purposes, Sentinel NetLab has known limitations.

## 1. 5GHz Operations
- **Passive Scanning**: The `CaptureDriver` currently hops channels sequentially. 5GHz bands have many more channels (DFS), increasing the cycle time and potentially missing short-duration attacks.
- **Hardware**: Reliability depends heavily on the WiFi adapter's varying support for 5GHz monitor mode on Linux.

## 2. Protected Management Frames (802.11w)
- **Impact**: Deauthentication attacks are ineffective against PMF-enabled clients.
- **Detection**: Our sensor can *detect* the attempt, but cannot verify if the victim was disconnected.

## 3. Encrypted Traffic
- **Scope**: Sentinel NetLab analyzes **metadata only** (Headers). It does not (and cannot) decrypt WPA2/WPA3 Data frames.
- **Blind Spot**: Attacks occurring inside the encrypted tunnel (e.g., ARP spoofing *after* association) are out of scope.

## 4. Performance
- **Throughput**: On Raspberry Pi 4, processing >500 frames/sec may cause packet drops.
- **Storage**: SQLite journal can become a bottleneck if upload link is down for extended periods.
