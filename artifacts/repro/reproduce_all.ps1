<#
.SYNOPSIS
    Master Reproduction Script for Sentinel NetLab
.DESCRIPTION
    Automates the full reproduction pipeline:
    1. Environment Verification
    2. Test Data Generation (Golden Vectors)
    3. Detection Logic Verification
.EXAMPLE
    .\reproduce_all.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Sentinel NetLab Reproduction Suite   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Environment Check
Write-Host "`n[1/3] Checking Environment..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python not found! Please install Python 3.11+"
}
Write-Host "Found: $pythonVersion" -ForegroundColor Green

# 2. Data Generation
Write-Host "`n[2/3] Generating Golden Vectors..." -ForegroundColor Yellow
try {
    python tests/data/generate_pcap.py
    if (Test-Path "tests/data/golden_vectors.pcap") {
        Write-Host "Success: golden_vectors.pcap generated." -ForegroundColor Green
    } else {
        throw "Failed to generate pcap file."
    }
} catch {
    Write-Error "Data generation failed: $_"
}

# 3. Detection Verification
Write-Host "`n[3/3] Verifying Detection Logic..." -ForegroundColor Yellow
Write-Host "Running detection scenarios against generated data..."
$pytestCmd = "pytest tests/integration/test_scenarios.py -v"
Invoke-Expression $pytestCmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[SUCCESS] All reproduction steps passed!" -ForegroundColor Green
    Write-Host "See docs/reproducibility/experiment_steps.md for details."
} else {
    Write-Error "`n[FAILURE] Detection verification failed."
}
