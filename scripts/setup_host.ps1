# PowerShell Script to help setup Windows Host for USB Passthrough
# Usage: Run as Administrator

Write-Host "=== WiFi Scanner Host Setup Helper ===" -ForegroundColor Cyan

# 1. Check for usbipd
if (Get-Command "usbipd" -ErrorAction SilentlyContinue) {
    Write-Host "[OK] usbipd is installed." -ForegroundColor Green
} else {
    Write-Host "[WARN] usbipd is NOT installed." -ForegroundColor Yellow
    Write-Host "Please install via: winget install dorssel.usbipd-win"
}

# 2. Check for VirtualBox/VMware
if (Get-Command "VirtualBox" -ErrorAction SilentlyContinue) {
    Write-Host "[OK] VirtualBox detected." -ForegroundColor Green
} elseif (Get-Command "vmware" -ErrorAction SilentlyContinue) {
    Write-Host "[OK] VMware Workstation detected." -ForegroundColor Green
} else {
    Write-Host "[INFO] No common Hypervisor in PATH. Ensure VirtualBox or VMware is installed." -ForegroundColor Yellow
}

# 3. List USB Devices
Write-Host "`n[INFO] Listing USB Devices..." -ForegroundColor Cyan
if (Get-Command "usbipd" -ErrorAction SilentlyContinue) {
    usbipd list
    Write-Host "`nTo attach a device to WSL2 (if using WSL):"
    Write-Host "  usbipd bind --busid <BUSID>"
    Write-Host "  usbipd attach --wsl --busid <BUSID>"
} else {
    Write-Host "Install usbipd to see device list easily, or check Device Manager."
}

Write-Host "`n[INFO] Setup Helper Complete."
Read-Host -Prompt "Press Enter to exit"
