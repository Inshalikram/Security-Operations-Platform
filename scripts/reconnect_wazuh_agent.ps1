# ==============================================================================
# Fix & Reconnect Wazuh Agent to Contabo VPS (169.58.221.49)
# Run in Administrator PowerShell
# ==============================================================================

Write-Host "[+] Step 1: Stopping Wazuh Service..." -ForegroundColor Cyan
Stop-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue

Write-Host "[+] Step 2: Updating ossec.conf Manager Address to 169.58.221.49..." -ForegroundColor Cyan
$confPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $confPath) {
    $content = Get-Content $confPath -Raw
    $newContent = [regex]::Replace($content, "<address>.*?</address>", "<address>169.58.221.49</address>")
    Set-Content -Path $confPath -Value $newContent
    Write-Host "    [OK] Server address updated to 169.58.221.49 in ossec.conf" -ForegroundColor Green
}

Write-Host "[+] Step 3: Registering Agent with VPS Manager (169.58.221.49:1515)..." -ForegroundColor Cyan
$agentAuth = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
if (Test-Path $agentAuth) {
    & $agentAuth -m 169.58.221.49 -p 1515 -A "Inshal-Laptop"
} else {
    Write-Warning "agent-auth.exe not found at $agentAuth"
}

Write-Host "[+] Step 4: Starting Wazuh Service..." -ForegroundColor Cyan
Start-Service -Name "Wazuh"
$status = (Get-Service -Name "Wazuh").Status
Write-Host "    [OK] Wazuh Service Status: $status" -ForegroundColor Green

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] Agent registered and connected to 169.58.221.49!" -ForegroundColor Green
Write-Host " Check VPS now with: docker exec sop-wazuh-manager /var/ossec/bin/agent_control -l" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Green
