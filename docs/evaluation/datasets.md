# Datasets & Test Vectors

To ensure reproducibility, Sentinel NetLab relies on synthetic datasets generated via `tests/data/generate_pcap.py`.

## 1. Golden Vectors (`golden_vectors.pcap`)
A standardized PCAP file containing:
- **Normal Traffic**: Beacons from authorized APs.
- **Evil Twin**: Beacons from an unauthorized AP with the same SSID but different BSSID.
- **Deauth Flood**: High-rate Deauthentication frames targeting a client.

How to generate:
```bash
python tests/data/generate_pcap.py
```
Output location: `tests/data/golden_vectors.pcap`

## 2. Real-World Captures (Not included)
Due to privacy regulations (GDPR/FERPA), we do **not** distribute real-world captures from the campus deployment. Users must generate their own baseline using the provided tools.

## 3. Labeling Policy
- **Attack**: Frames injected by Test Vector Generator.
- **Benign**: Frames generated as "Background Traffic".
- **Unknown**: Ambient RF noise (if capturing live).
