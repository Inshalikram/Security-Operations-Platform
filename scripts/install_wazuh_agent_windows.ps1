# ==============================================================================
# Automated Wazuh Agent 4.9.0 Installer for Windows
# Connects this workstation directly to the SOC Platform VPS (169.58.221.49)
# Run in PowerShell AS ADMINISTRATOR
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     SOC Platform - Windows Endpoint EDR Agent Installer (Wazuh)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$ManagerIP = "169.58.221.49"
$AgentName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "Inshal-Laptop" }
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
$MsiPath = "$env:TEMP\wazuh-agent-4.9.0.msi"

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[-] Please run this PowerShell window as Administrator!"
    Write-Host "    Right-click on PowerShell -> 'Run as administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Step 1: Testing connectivity to Wazuh Manager ($ManagerIP)..." -ForegroundColor Green
$test1514 = Test-NetConnection -ComputerName $ManagerIP -Port 1514 -InformationLevel Quiet
$test1515 = Test-NetConnection -ComputerName $ManagerIP -Port 1515 -InformationLevel Quiet

if ($test1514 -and $test1515) {
    Write-Host "    [OK] Connection to ports 1514 and 1515 succeeded!" -ForegroundColor Green
} else {
    Write-Warning "[-] Warning: Could not reach port 1514 or 1515. Proceeding anyway..."
}

Write-Host "[+] Step 2: Downloading official Wazuh Agent 4.9.0 MSI installer..." -ForegroundColor Green
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $MsiPath -UseBasicParsing
    Write-Host "    [OK] Installer downloaded to $MsiPath" -ForegroundColor Green
} catch {
    Write-Error "[-] Failed to download installer: $_"
    exit 1
}

Write-Host "[+] Step 3: Installing Wazuh Agent and enrolling as '$AgentName'..." -ForegroundColor Green
$arguments = "/i `"$MsiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`""
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "    [OK] Wazuh Agent successfully installed!" -ForegroundColor Green
} else {
    Write-Warning "[-] msiexec exited with code $($process.ExitCode). Checking service..."
}

Write-Host "[+] Step 4: Starting Wazuh Agent service (WazuhSvc)..." -ForegroundColor Green
try {
    Start-Service -Name "Wazuh" -ErrorAction Stop
    $service = Get-Service -Name "Wazuh"
    Write-Host "    [OK] Wazuh Agent Service Status: $($service.Status)" -ForegroundColor Green
} catch {
    Write-Host "    Starting service with net start..."
    cmd.exe /c "net start WazuhSvc"
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   [SUCCESS] Laptop is now enrolled into your SOC Platform!" -ForegroundColor Green
Write-Host "   Manager IP:   $ManagerIP" -ForegroundColor White
Write-Host "   Agent Name:   $AgentName" -ForegroundColor White
Write-Host "   Active Alerts will now stream directly to your SOC Dashboard!" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
