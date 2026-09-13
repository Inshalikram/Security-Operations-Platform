# Script to link Windows Defender and Desktop to Wazuh Agent
$confPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (-not (Test-Path $confPath)) {
    Write-Host "ossec.conf not found at $confPath" -ForegroundColor Red
    exit 1
}

$raw = Get-Content $confPath -Raw

# 1. Add Defender Eventchannel if not present
if ($raw -notmatch "Microsoft-Windows-Windows Defender/Operational") {
    $defenderBlock = @"
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
    $raw = $raw -replace "(<location>System</location>\s*<log_format>eventchannel</log_format>\s*</localfile>)", "`$1`r`n$defenderBlock"
    Write-Host "[+] Added Windows Defender Event Channel to ossec.conf" -ForegroundColor Green
} else {
    Write-Host "[*] Windows Defender Event Channel is already present." -ForegroundColor Yellow
}

# 2. Add Desktop directory to realtime syscheck if not present
$desktopPath = "$env:USERPROFILE\Desktop"
if ($raw -notmatch [regex]::Escape($desktopPath)) {
    $dirBlock = "    <directories realtime=`"yes`">$desktopPath</directories>"
    $raw = $raw -replace "(<directories realtime=`"yes`>.*?Startup</directories>)", "`$1`r`n$dirBlock"
    Write-Host "[+] Added Desktop ($desktopPath) to real-time Syscheck monitoring" -ForegroundColor Green
}

# 3. Save updated config
Set-Content -Path $confPath -Value $raw -Encoding utf8
Write-Host "[+] Saved ossec.conf" -ForegroundColor Green

# 4. Restart Wazuh Service
Restart-Service -Name WazuhSvc
Write-Host "[+] WazuhSvc successfully restarted!" -ForegroundColor Green
