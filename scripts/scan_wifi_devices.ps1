# Scan WiFi Subnet for Active Devices
$gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
$localIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi" -ErrorAction SilentlyContinue).IPAddress
if (-not $localIP) {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "192.168.*" }).IPAddress | Select-Object -First 1
}

$subnetPrefix = $localIP.Substring(0, $localIP.LastIndexOf('.') + 1)
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  WiFi Network Scanner (Subnet: $subnetPrefix*)" -ForegroundColor Cyan
Write-Host "  Your Laptop IP: $localIP" -ForegroundColor Yellow
Write-Host "  Router / Gateway: $gateway" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Scanning network for active devices..." -ForegroundColor Gray

# Quick async ping sweep to populate ARP cache
1..254 | ForEach-Object {
    $target = "$subnetPrefix$_"
    $p = New-Object System.Net.NetworkInformation.Ping
    [void]$p.SendAsync($target, 250, $null)
}
Start-Sleep -Seconds 3

# Retrieve active devices from ARP table
$neighbors = Get-NetNeighbor -AddressFamily IPv4 | Where-Object { 
    $_.IPAddress -like "$subnetPrefix*" -and 
    $_.State -ne "Unreachable" -and 
    $_.IPAddress -ne "$subnetPrefix" + "255" 
} | Sort-Object { [version]$_.IPAddress }

$results = foreach ($dev in $neighbors) {
    $hostname = ""
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($dev.IPAddress).HostName
    } catch {
        $hostname = "Unknown / Device"
    }

    $deviceType = "Device"
    if ($dev.IPAddress -eq $gateway) { $deviceType = "WiFi Router / Gateway" }
    elseif ($dev.IPAddress -eq $localIP) { $deviceType = "This Laptop (Inshal)" }

    [PSCustomObject]@{
        IPAddress = $dev.IPAddress
        MACAddress = $dev.LinkLayerAddress
        DeviceType = $deviceType
        HostName = $hostname
        Status = "Online"
    }
}

$results | Format-Table -AutoSize
Write-Host "Total Active Devices Found: $($results.Count)" -ForegroundColor Green
