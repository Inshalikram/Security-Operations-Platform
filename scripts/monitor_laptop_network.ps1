# ==============================================================================
# SOC Platform — Real-Time Laptop Network Traffic Inspector & Sensor
# Inspects every TCP connection entering and leaving this laptop in real-time.
# Flags suspicious ports, anomalous processes, and ships alerts to the SOC Dashboard.
# ==============================================================================

param(
    [switch]$Once,
    [int]$IntervalSeconds = 4,
    [string]$SocApiUrl = "https://api.169-58-221-49.nip.io",
    [string]$ApiKey = "mysecretkey123",
    [switch]$SimulateTestAlert
)

$Continuous = -not $Once

$logDir = "$PSScriptRoot\..\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$alertLog = "$logDir\laptop_network_alerts.log"

$SUSPICIOUS_PORTS = @(4444, 5555, 1337, 6667, 31337, 8888, 9999, 23, 21, 3389, 445, 135)
$SUSPICIOUS_PROCS = @("powershell", "pwsh", "cmd", "certutil", "mshta", "cscript", "wscript", "rundll32", "regsvr32")
$KNOWN_SAFE_IPS = @("127.0.0.1", "0.0.0.0", "::1")

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  SOC PLATFORM - LAPTOP LIVE NETWORK TRAFFIC INSPECTOR AND SENSOR" -ForegroundColor Cyan
Write-Host "  Status: Active and Monitoring WiFi and LAN Network Interfaces" -ForegroundColor Green
Write-Host "  Destination SOC Backend: $SocApiUrl" -ForegroundColor Yellow
Write-Host "  Log Destination: $alertLog" -ForegroundColor Gray
Write-Host "============================================================================" -ForegroundColor Cyan

function Send-SocAlert {
    param(
        [hashtable]$AlertData
    )
    try {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        $AlertData | ConvertTo-Json -Compress | Set-Content -Path $tmpFile -Encoding ASCII
        
        $httpCode = curl.exe -k -s -w "%{http_code}" -X POST "$SocApiUrl/alerts" `
            -H "Content-Type: application/json" `
            -H "X-API-Key: $ApiKey" `
            --data-binary "@$tmpFile" `
            -m 10
            
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
        return $httpCode
    } catch {
        return "ERROR: $_"
    }
}

# ── Safe Test Simulation Mode ──
if ($SimulateTestAlert) {
    Write-Host ""
    Write-Host "[*] Running Safe Laptop Network Test Simulation..." -ForegroundColor Yellow
    Write-Host "[*] Simulating detection of suspicious outbound C2 socket from test script..." -ForegroundColor Yellow
    
    $testPayload = @{
        title = "Laptop Network Threat: Suspicious process (powershell.exe) socket to 198.51.100.23:4444"
        alert_type = "laptop-network"
        severity = "critical"
        source_ip = "192.168.0.203"
        dest_ip = "198.51.100.23"
        detail = "Safe Test Simulation: Process powershell.exe established socket to known C2 port 4444"
    }

    $resp = Send-SocAlert -AlertData $testPayload
    Write-Host "[+] Shipped simulated alert to SOC Backend ($SocApiUrl) - HTTP Status: $resp" -ForegroundColor Green
    Write-Host "[OK] Test alert sent to SOC Dashboard. Check https://app.169-58-221-49.nip.io/alerts" -ForegroundColor Cyan
    exit 0
}

Write-Host "Press Ctrl + C anytime to stop monitoring.`n" -ForegroundColor Gray

function Inspect-NetworkConnections {
    $connections = Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue
    $activeCount = ($connections | Where-Object { $_.State -eq "Established" }).Count
    
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Scanning active network sockets... ($activeCount Established Connections)" -ForegroundColor DarkGray

    $results = foreach ($conn in $connections) {
        $procName = "Unknown"
        if ($conn.OwningProcess -and $conn.OwningProcess -ne 0) {
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($proc) { $procName = $proc.ProcessName }
            } catch {
                $procName = "PID:$($conn.OwningProcess)"
            }
        }

        $remoteIp = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        $localPort = $conn.LocalPort
        $state = $conn.State

        # Ignore localhost/loopback
        if ($remoteIp -in $KNOWN_SAFE_IPS -or $remoteIp -like "127.*") { continue }

        $threatLevel = "Normal"
        $threatReason = ""

        # Rule 1: Suspicious C2 / Hacker ports
        if ($remotePort -in $SUSPICIOUS_PORTS) {
            $threatLevel = "High"
            $threatReason = "Connection to known C2/Trojan/Metasploit port ($remotePort)"
        }

        # Rule 2: Suspicious script/interpreter opening network sockets
        if ($procName.ToLower() -in $SUSPICIOUS_PROCS -and $state -eq "Established") {
            $threatLevel = "Critical"
            $threatReason = "Suspicious script engine ($procName) established outbound network socket to $remoteIp"
        }

        # Rule 3: Inbound SMB/RPC probing from local or foreign network
        if ($state -eq "Listen" -and $localPort -in @(445, 135, 3389)) {
            # listening on sensitive ports
        }

        if ($threatLevel -in @("High", "Critical")) {
            Write-Host ""
            Write-Host "[!] NETWORK THREAT DETECTED ON LAPTOP!" -ForegroundColor Red
            Write-Host "    -> Process:     $procName (PID: $($conn.OwningProcess))" -ForegroundColor Yellow
            Write-Host "    -> Connection:  $($conn.LocalAddress):$($localPort) -> $($remoteIp):$($remotePort)" -ForegroundColor Yellow
            Write-Host "    -> Reason:      $threatReason" -ForegroundColor Red

            $alertPayload = @{
                timestamp = (Get-Date).ToString("o")
                source = "laptop-network"
                agent_host = $env:COMPUTERNAME
                process = $procName
                pid = $conn.OwningProcess
                local_ip = $conn.LocalAddress
                local_port = $localPort
                remote_ip = $remoteIp
                remote_port = $remotePort
                threat_level = $threatLevel
                reason = $threatReason
            }

            $alertJson = $alertPayload | ConvertTo-Json -Compress
            Add-Content -Path $alertLog -Value $alertJson -Encoding utf8

            # Try reporting to SOC Backend
            $backendPayload = @{
                title = "Laptop Network Threat: $threatReason"
                alert_type = "laptop-network"
                severity = if ($threatLevel -eq "Critical") { "critical" } else { "high" }
                source_ip = $conn.LocalAddress
                dest_ip = $remoteIp
                detail = "$procName connected to $($remoteIp):$($remotePort) - $threatReason"
            }
            $socStatus = Send-SocAlert -AlertData $backendPayload
            Write-Host "    -> SOC Backend Response: $socStatus" -ForegroundColor DarkGray
        }

        [PSCustomObject]@{
            Process = $procName
            LocalSocket = "$($conn.LocalAddress):$($localPort)"
            RemoteSocket = "$($remoteIp):$($remotePort)"
            State = $state
            Status = $threatLevel
        }
    }

    # Display clean summary of top 8 active public/foreign connections
    $foreign = $results | Where-Object { $_.RemoteSocket -notlike "*:0" -and $_.RemoteSocket -notlike "192.168.*" -and $_.RemoteSocket -notlike "10.*" }
    if ($foreign) {
        $foreign | Select-Object -First 8 | Format-Table -AutoSize
    }
}

# Run loop
do {
    Inspect-NetworkConnections
    if ($Continuous) {
        Start-Sleep -Seconds $IntervalSeconds
    }
} while ($Continuous)
