#!/usr/bin/env python3
# check_driver.py - Diagnostic script
import os
import subprocess


def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.stdout + p.stderr

print("=== LSUSB ===")
print(run("lsusb"))

print("\n=== IW DEV ===")
print(run("iw dev"))

print("\n=== Iwconfig ===")
print(run("iwconfig"))

print("\n=== LSMOD (common wifi drivers) ===")
print(run("lsmod | egrep 'ath9k_htc|ath9k|rt2800|cfg80211|mac80211' || true"))

fwdir = "/lib/firmware/ath9k_htc"
print(f"\n=== Firmware dir: {fwdir} ===")
if os.path.isdir(fwdir):
    print(run(f"ls -la {fwdir}"))
else:
    print("Firmware dir NOT FOUND; consider installing firmware-atheros package.")

print("\n=== DMESG last 60 lines (filter wifi) ===")
print(run("dmesg | tail -n 60 | egrep -i 'ath|firmware|wlan|usb' || true"))

print("\n=== SUGGESTED ACTIONS ===")
print("1) If module missing try: sudo modprobe ath9k_htc (may fail if kernel lack support).")
print("2) If firmware missing: sudo apt install firmware-atheros (on Debian/Kali).")
print("3) If not fixable: use physical Linux sensor (Raspberry Pi) or mock mode.")
