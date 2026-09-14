# ==============================================================================
# SOC Platform - Uninstall Laptop Network Traffic Sensor
# Stops the background sensor and removes it from Windows Startup.
# ==============================================================================

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  SOC PLATFORM - STOPPING AND UNINSTALLING LAPTOP NETWORK SENSOR            " -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

# 1. Terminate background processes
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*monitor_laptop_network.ps1*" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Terminated running sensor process (PID: $($_.ProcessId))" -ForegroundColor Green
}

# 2. Remove startup launcher
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$vbsLauncher = "$startupFolder\soc_laptop_network_sensor.vbs"

if (Test-Path $vbsLauncher) {
    Remove-Item -Path $vbsLauncher -Force
    Write-Host "[OK] Removed autostart launcher from Windows Startup." -ForegroundColor Green
} else {
    Write-Host "[INFO] No autostart launcher found in Startup." -ForegroundColor Gray
}

Write-Host ""
Write-Host "[DONE] Laptop Network Traffic Sensor uninstalled successfully." -ForegroundColor Cyan
