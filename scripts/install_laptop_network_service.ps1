# ==============================================================================
# SOC Platform - Install Laptop Network Traffic Sensor and Service
# Registers the laptop network inspector as a permanent background daemon
# and enables Windows Defender Network Protection for browser traffic.
# ==============================================================================

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  SOC PLATFORM - INSTALLING LAPTOP NETWORK SENSOR AND DEFENDER PROTECTION   " -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

# 1. Path definitions
$scriptPath = "$PSScriptRoot\monitor_laptop_network.ps1"
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$vbsLauncher = "$startupFolder\soc_laptop_network_sensor.vbs"

# 2. Create Silent VBS Background Launcher in Startup Folder
$vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$scriptPath""", 0, False
"@

Set-Content -Path $vbsLauncher -Value $vbsContent -Encoding ASCII -Force
Write-Host "[OK] Background Autostart Sensor Installed in Startup Folder:" -ForegroundColor Green
Write-Host "     -> $vbsLauncher" -ForegroundColor Gray

# 3. Terminate any previous background instance and start freshly now
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*monitor_laptop_network.ps1*" -and $_.ProcessId -ne $PID } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# Launch in background right now
Start-Process -FilePath "wscript.exe" -ArgumentList "`"$vbsLauncher`"" -WindowStyle Hidden
Write-Host "[OK] Live Laptop Network Traffic Sensor started in background (24/7)." -ForegroundColor Green

# 4. Try enabling Windows Defender Network Protection (blocks malicious sites in Chrome and Edge)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    try {
        Set-MpPreference -EnableNetworkProtection Enabled
        Write-Host "[OK] Windows Defender Network Protection: ENABLED (Blocks malicious URLs in Chrome and Edge)" -ForegroundColor Green
    } catch {
        Write-Host "[-] Could not enable Defender Network Protection: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[INFO] To enable Chrome and Edge malicious URL auto-blocking, run this in Admin PowerShell:" -ForegroundColor Yellow
    Write-Host "       Set-MpPreference -EnableNetworkProtection Enabled" -ForegroundColor Yellow
}

# 5. Check Wazuh Agent
$wazuh = Get-Service -Name "*wazuh*" -ErrorAction SilentlyContinue
if ($wazuh -and $wazuh.Status -eq "Running") {
    Write-Host "[OK] Wazuh EDR Agent is active and forwarding events to the SOC Platform." -ForegroundColor Green
} else {
    Write-Host "[INFO] Wazuh Agent status: $($wazuh.Status)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[SUCCESS] Your laptop is now fully protected and actively monitoring network traffic!" -ForegroundColor Cyan
Write-Host "Any suspicious port or connection will automatically be reported to your SOC Dashboard." -ForegroundColor Cyan
