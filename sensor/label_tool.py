"""
Labeling Tool for Sentinel NetLab.
Collects SOC analyst labels for training the Risk ML model.

Usage:
    python label_tool.py --input data/networks.json --output data/labeled.json
"""

import argparse
import json
import os


def display_network(net: dict, index: int, total: int) -> None:
    """Print network info for labeling."""
    print("\n" + "=" * 60)
    print(f"  Network {index + 1} / {total}")
    print("=" * 60)
    print(f"  SSID:       {net.get('ssid', '<hidden>')}")
    print(f"  BSSID:      {net.get('bssid', 'Unknown')}")
    print(f"  Encryption: {net.get('encryption', 'Unknown')}")
    print(f"  Signal:     {net.get('signal', 'N/A')} dBm")
    print(f"  Channel:    {net.get('channel', 'N/A')}")
    print(f"  Vendor:     {net.get('vendor', 'Unknown')}")
    print(f"  WPS:        {'Yes' if net.get('wps_enabled') else 'No'}")
    print("=" * 60)


def get_label() -> str:
    """Prompt user for label."""
    while True:
        choice = input("  Label [L]ow / [M]edium / [H]igh / [S]kip: ").strip().upper()
        if choice in ["L", "LOW"]:
            return "LOW"
        elif choice in ["M", "MEDIUM"]:
            return "MEDIUM"
        elif choice in ["H", "HIGH"]:
            return "HIGH"
        elif choice in ["S", "SKIP"]:
            return None
        else:
            print("  Invalid input. Use L/M/H/S.")


def run_labeling(input_path: str, output_path: str) -> None:
    """Main labeling loop."""
    # Load data
    with open(input_path) as f:
        networks = json.load(f)

    if isinstance(networks, dict) and "networks" in networks:
        networks = networks["networks"]

    labeled = []
    total = len(networks)

    print(f"\nLoaded {total} networks from {input_path}")
    print("Enter labels for each network. Press Ctrl+C to save and exit.\n")

    try:
        for i, net in enumerate(networks):
            display_network(net, i, total)
            label = get_label()

            if label:
                labeled.append(
                    {
                        "bssid": net.get("bssid"),
                        "ssid": net.get("ssid"),
                        "encryption": net.get("encryption"),
                        "signal": net.get("signal"),
                        "vendor": net.get("vendor"),
                        "label": label,
                    }
                )
                print(f"  -> Labeled as {label}")
            else:
                print("  -> Skipped")

    except KeyboardInterrupt:
        print("\n\nLabeling interrupted.")

    # Save
    with open(output_path, "w") as f:
        json.dump(labeled, f, indent=2)

    print(f"\nSaved {len(labeled)} labeled networks to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label WiFi networks for ML training")
    parser.add_argument(
        "--input", "-i", required=True, help="Input JSON file with networks"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="data/labeled_networks.json",
        help="Output file for labeled data",
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        exit(1)

    run_labeling(args.input, args.output)
