# Live Attack Simulation Script for SOC Platform Evaluation
# Dispatches plaintext HTTP and ICMP attack signatures directly to Suricata IDS on port 80

$vpsIp = "169.58.221.49"
$httpTarget = "http://$vpsIp"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SOC Platform Live Intrusion Simulation (Suricata IDS)   " -ForegroundColor Cyan
Write-Host "  Target: $httpTarget (Plaintext Port 80 for NIDS DPI)    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "`n[1/8] Simulating ICMP Ping sweep..." -ForegroundColor Yellow
Test-Connection -ComputerName $vpsIp -Count 2 | Out-Null
Write-Host "[+] ICMP echo packets dispatched! (Signature: 'ICMP Ping Detected')" -ForegroundColor Green

Write-Host "`n[2/8] Simulating SQL Injection probe via 'sqlmap'..." -ForegroundColor Yellow
$sqliPayload = "$httpTarget/?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"
curl.exe -s -A "sqlmap/1.7.2#stable" "$sqliPayload" -m 3 | Out-Null
Write-Host "[+] SQLMap probe dispatched! (Signature: 'Suspicious User-Agent - sqlmap')" -ForegroundColor Green

Write-Host "`n[3/8] Simulating Directory Traversal probe (Nikto scanner)..." -ForegroundColor Yellow
$traversal = "$httpTarget/../../etc/passwd"
curl.exe -s -A "Nikto/2.1.6" "$traversal" -m 3 | Out-Null
Write-Host "[+] Nikto probe dispatched! (Signature: 'Nikto Web Scanner' & 'Directory Traversal')" -ForegroundColor Green

Write-Host "`n[4/8] Simulating Port Scan burst (25 rapid probes to trip threshold)..." -ForegroundColor Yellow
1..25 | ForEach-Object {
    curl.exe -s "$httpTarget" -m 1 | Out-Null
}
Write-Host "[+] Port scan burst generated! (Signature: 'Possible Port Scan Detected')" -ForegroundColor Green

Write-Host "`n[5/8] Simulating SSH Brute Force attempt (Port 22 rapid probes)..." -ForegroundColor Yellow
1..7 | ForEach-Object {
    curl.exe -s "http://$vpsIp`:22" -m 1 | Out-Null
}
Write-Host "[+] SSH Brute Force probes dispatched! (Signature: 'SSH Brute Force Attempt')" -ForegroundColor Green

Write-Host "`n[6/8] Simulating MinIO Console Brute Force attempt (Port 9001 rapid probes)..." -ForegroundColor Yellow
1..8 | ForEach-Object {
    curl.exe -s "http://$vpsIp`:9001" -m 1 | Out-Null
}
Write-Host "[+] MinIO Brute Force probes dispatched! (Signature: 'MinIO Storage & Console Brute Force Attempt')" -ForegroundColor Green

Write-Host "`n[7/8] Simulating Sensitive File Snooping probe (.env)..." -ForegroundColor Yellow
curl.exe -s "$httpTarget/.env" -m 3 | Out-Null
Write-Host "[+] Sensitive file probe dispatched! (Signature: 'Sensitive Information Snooping (.env / .git)')" -ForegroundColor Green

Write-Host "`n[8/8] Simulating OS Command Injection probe (whoami)..." -ForegroundColor Yellow
curl.exe -s "$httpTarget/api/exec?cmd=whoami" -m 3 | Out-Null
Write-Host "[+] Command injection probe dispatched! (Signature: 'OS Command Injection Probe (whoami / shell)')" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  All Intrusion Simulations Complete!" -ForegroundColor Green
Write-Host "  Suricata NIDS has logged the attacks across all services." -ForegroundColor White
Write-Host "  Wait ~30-60 seconds for the backend watchdog cycle," -ForegroundColor White
Write-Host "  then refresh your browser (press F5):" -ForegroundColor White
Write-Host "  1. Alerts Page: https://app.169-58-221-49.nip.io/alerts" -ForegroundColor Yellow
Write-Host "  2. SOC Dashboard: https://app.169-58-221-49.nip.io/dashboard" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
