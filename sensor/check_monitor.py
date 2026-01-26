#!/usr/bin/env python3
import subprocess
import sys
import os

def check_root():
    if os.geteuid() != 0:
        print("[-] Script can chay voi quyen root (sudo).")
        sys.exit(1)

def get_wireless_interfaces():
    print("[*] Dang tim kiem wireless interfaces...")
    try:
        # Su dung iw dev de lay danh sach
        result = subprocess.check_output(["iw", "dev"], stderr=subprocess.STDOUT).decode()
        interfaces = []
        for line in result.split('\n'):
            if "Interface" in line:
                interfaces.append(line.split()[1])
        return interfaces
    except FileNotFoundError:
        print("[-] Khong tim thay lenh 'iw'. Hay cai dat 'wireless-tools' hoac 'iw'.")
        return []
    except Exception as e:
        print(f"[-] Loi khi quet interface: {e}")
        return []

def check_monitor_mode_support(interface):
    print(f"[*] Dang kiem tra Monitor Mode support cho {interface}...")
    
    # Buoc 1: Down interface
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
    except subprocess.CalledProcessError:
        print(f"[-] Khong the down interface {interface}")
        return False

    # Buoc 2: Thu set mode monitor
    try:
        subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], check=True)
        print(f"[+] {interface} HO TRO Monitor Mode!")
        
        # Restore managed mode (optional, de tra lai trang thai ban dau)
        # subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True)
        
        # Up interface lai
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"[-] {interface} KHONG ho tro hoac loi khi set Monitor Mode.")
        # Thu restore lai
        subprocess.run(["ip", "link", "set", interface, "up"], check=False)
        return False

def main():
    print("=== WIFI MONITOR MODE CHECKER ===")
    check_root()
    
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[-] Khong tim thay wireless interface nao.")
        print("    Goi y: Kiem tra kiet noi USB passthrough (usbipd attach).")
        print("    Kiem tra 'lsusb' xem da nhan thiet bi chua.")
        return

    print(f"[+] Tim thay interfaces: {', '.join(interfaces)}")
    
    supported_count = 0
    for iface in interfaces:
        if check_monitor_mode_support(iface):
            supported_count += 1
            print(f"[SUCCESS] Phat hien interface manh: {iface}")
            
    if supported_count == 0:
        print("\n[-] Khong co interface nao ho tro Monitor Mode.")
    else:
        print(f"\n[+] Co {supported_count} interface san sang cho viec giam sat.")

if __name__ == "__main__":
    main()
