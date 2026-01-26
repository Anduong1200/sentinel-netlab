<#
.SYNOPSIS
    Script hỗ trợ setup môi trường cho dự án Hybrid WiFi Monitor.
    
.DESCRIPTION
    Script này kiểm tra và hướng dẫn cài đặt:
    1. WSL2
    2. Kali Linux Distro
    3. usbipd-win
    
    Cần chạy với quyền Administrator.
#>

# Kiểm tra quyền Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Vui long chay script nay voi quyen Administrator!"
    exit
}

Write-Host "=== SETUP HELPER: HYBRID WIFI MONITOR ===" -ForegroundColor Cyan

# 1. Kiểm tra WSL
Write-Host "`n[1/3] Kiem tra WSL..."
if (Get-Command "wsl" -ErrorAction SilentlyContinue) {
    Write-Host "OK: WSL da duoc cai dat." -ForegroundColor Green
    $wslStatus = wsl --status
    if ($wslStatus -match "Default Version: 2") {
        Write-Host "OK: WSL Version 2 la mac dinh." -ForegroundColor Green
    } else {
        Write-Warning "WSL mac dinh khong phai Version 2. Ban nen chay 'wsl --set-default-version 2'"
    }
} else {
    Write-Warning "WSL chua duoc cai dat."
    $install = Read-Host "Ban co muon cai dat WSL ngay bay gio khong? (Y/N)"
    if ($install -eq 'Y') {
        wsl --install
        Write-Host "Vui long khoi dong lai may tinh sau khi cai dat xong!" -ForegroundColor Yellow
        exit
    }
}

# 2. Kiểm tra Kali Linux
Write-Host "`n[2/3] Kiem tra Kali Linux..."
$list = wsl --list --quiet 2>$null
if ($list -match "kali-linux") {
    Write-Host "OK: Kali Linux da duoc cai dat." -ForegroundColor Green
} else {
    Write-Warning "Kali Linux chua duoc cai dat."
    Write-Host "Hay chay lenh sau de cai dat: 'wsl --install -d kali-linux'" -ForegroundColor Yellow
}

# 3. Kiểm tra usbipd
Write-Host "`n[3/3] Kiem tra usbipd-win..."
if (Get-Command "usbipd" -ErrorAction SilentlyContinue) {
    Write-Host "OK: usbipd-win da duoc cai dat." -ForegroundColor Green
} else {
    Write-Warning "usbipd-win chua duoc cai dat."
    $installUsb = Read-Host "Ban co muon cai dat usbipd-win qua winget khong? (Y/N)"
    if ($installUsb -eq 'Y') {
        winget install dorssel.usbipd-win
    }
}

Write-Host "`n=== HOAN TAT KIEM TRA ===" -ForegroundColor Cyan
Write-Host "Tiep theo:"
Write-Host "1. Cam USB WiFi."
Write-Host "2. Chay 'usbipd list' de lay BUSID."
Write-Host "3. Chay 'usbipd bind --busid <BUSID>'"
Write-Host "4. Chay 'usbipd attach --wsl --busid <BUSID>'"
Write-Host "5. Vao WSL va chay setup ben trong Linux."
Pause
