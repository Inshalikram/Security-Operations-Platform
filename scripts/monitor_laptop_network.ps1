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
$SUSPICIOUS_IPS = @("198.51.100.23", "203.0.113.5", "185.220.101.5", "192.42.116.16", "185.156.73.54", "45.154.255.88")
$global:AlertDeduplication = @{}

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
        $tmpResp = [System.IO.Path]::GetTempFileName()
        $AlertData | ConvertTo-Json -Compress | Set-Content -Path $tmpFile -Encoding ASCII
        
        $httpCode = curl.exe -k -s -o "$tmpResp" -w "%{http_code}" -X POST "$SocApiUrl/alerts" `
            -H "Content-Type: application/json" `
            -H "X-API-Key: $ApiKey" `
            --data-binary "@$tmpFile" `
            -m 15
            
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
        Remove-Item $tmpResp -Force -ErrorAction SilentlyContinue
        if ($null -eq $httpCode) { return "ERROR" }
        return $httpCode.Trim()
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
    if ($resp -in @("200", "201")) {
        Write-Host "[+] Shipped simulated alert to SOC Backend ($SocApiUrl) - HTTP Status: $resp OK" -ForegroundColor Green
        Write-Host "[OK] Test alert sent to SOC Dashboard. Check https://app.169-58-221-49.nip.io/alerts" -ForegroundColor Cyan
    } elseif ($resp -eq "401") {
        Write-Host "[!] Shipped simulated alert to SOC Backend ($SocApiUrl) - HTTP Status: 401 Unauthorized" -ForegroundColor Red
        Write-Host "    Reason: The VPS backend container is running an older image without X-API-Key authentication." -ForegroundColor Yellow
        Write-Host "    Action Required on VPS terminal:" -ForegroundColor Yellow
        Write-Host "         cd /opt/soc" -ForegroundColor Cyan
        Write-Host "         git pull origin main" -ForegroundColor Cyan
        Write-Host "         docker compose up -d --build backend" -ForegroundColor Cyan
    } else {
        Write-Host "[!] SOC Backend Response: HTTP Status $resp" -ForegroundColor Red
    }
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

        # Rule 4: Known Threat / Malicious IP matching
        if ($remoteIp -in $SUSPICIOUS_IPS) {
            $threatLevel = "High"
            $threatReason = "Connection to known threat-intel IP ($remoteIp)"
        }

        # Rule 5: Browser connection to unusual non-web ports
        if ($procName.ToLower() -in @("chrome", "msedge", "firefox", "brave") -and $remotePort -in $SUSPICIOUS_PORTS) {
            $threatLevel = "High"
            $threatReason = "Browser ($procName) established connection to suspicious port ($remotePort)"
        }

        if ($threatLevel -in @("High", "Critical")) {
            $dedupKey = "$procName-$remoteIp-$remotePort"
            $lastSent = $global:AlertDeduplication[$dedupKey]
            $shouldAlert = ($null -eq $lastSent) -or ((Get-Date) - $lastSent).TotalMinutes -gt 3

            Write-Host ""
            Write-Host "[!] NETWORK THREAT DETECTED ON LAPTOP!" -ForegroundColor Red
            Write-Host "    -> Process:     $procName (PID: $($conn.OwningProcess))" -ForegroundColor Yellow
            Write-Host "    -> Connection:  $($conn.LocalAddress):$($localPort) -> $($remoteIp):$($remotePort)" -ForegroundColor Yellow
            Write-Host "    -> Reason:      $threatReason" -ForegroundColor Red

            if ($shouldAlert) {
                $global:AlertDeduplication[$dedupKey] = Get-Date

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

function Inspect-DefenderBlocks {
    try {
        $recentEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = 1125, 1126, 1116, 1117
            StartTime = (Get-Date).AddMinutes(-5)
        } -ErrorAction SilentlyContinue

        foreach ($evt in $recentEvents) {
            $dedupKey = "defender-$($evt.Id)-$($evt.RecordId)"
            if ($global:AlertDeduplication[$dedupKey]) { continue }
            $global:AlertDeduplication[$dedupKey] = Get-Date

            $msg = $evt.Message
            $target = "Unknown"
            $proc = "Unknown"
            $malware = ""

            if ($msg -match 'Destination:\s*(.+)') { $target = $matches[1].Trim() }
            if ($msg -match 'Process Name:\s*(.+)') { $proc = [System.IO.Path]::GetFileName($matches[1].Trim()) }
            if ($msg -match 'Name:\s*(.+)') { $malware = $matches[1].Trim() }

            $isWebBlock = $evt.Id -in @(1125, 1126)
            $title = if ($isWebBlock) {
                "Malicious URL Blocked: $target ($proc)"
            } else {
                "Malware Quarantined: $malware ($proc)"
            }

            Write-Host ""
            Write-Host "[!] DEFENDER THREAT DETECTED ON LAPTOP!" -ForegroundColor Red
            Write-Host "    -> Threat:  $title" -ForegroundColor Yellow
            Write-Host "    -> Target:  $target" -ForegroundColor Yellow

            $backendPayload = @{
                title = "Laptop Threat: $title"
                alert_type = "laptop-network"
                severity = "critical"
                source_ip = "192.168.0.203"
                dest_ip = if ($target -ne "Unknown") { $target } else { "Local Machine" }
                detail = "Windows Defender Protection actively intercepted and mitigated threat from $proc. (Event ID: $($evt.Id))"
            }
            $socStatus = Send-SocAlert -AlertData $backendPayload
            Write-Host "    -> SOC Backend Response: $socStatus" -ForegroundColor DarkGray
        }
    } catch {
        # ignore event log access hiccups
    }
}

# Run loop
do {
    Inspect-DefenderBlocks
    Inspect-NetworkConnections
    if ($Continuous) {
        Start-Sleep -Seconds $IntervalSeconds
    }
} while ($Continuous)
