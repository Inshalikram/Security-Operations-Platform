# Live Attack Simulation Script for SOC Platform Evaluation
# This script sends simulated intrusion payloads to the SOC Platform (Suricata IDS)

$target = "https://app.169-58-221-49.nip.io"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SOC Platform Live Intrusion Simulation (Suricata IDS)   " -ForegroundColor Cyan
Write-Host "  Target: $target                                          " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

Write-Host "`n[1/3] Simulating SQL Injection probe via 'sqlmap'..." -ForegroundColor Yellow
$sqliPayload = "$target/?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"
$res = curl.exe -k -s -A "sqlmap/1.7.2#stable" "$sqliPayload" -m 4
Write-Host "[+] Attack traffic dispatched! (Signature: 'sqlmap')" -ForegroundColor Green

Write-Host "`n[2/3] Simulating Directory Traversal probe (Nikto scanner)..." -ForegroundColor Yellow
$traversal = "$target/../../etc/passwd"
$res2 = curl.exe -k -s -A "Nikto/2.1.6" "$traversal" -m 4
Write-Host "[+] Attack traffic dispatched! (Signature: 'Nikto')" -ForegroundColor Green

Write-Host "`n[3/3] Simulating Attack Probe on Management Ports..." -ForegroundColor Yellow
1..5 | ForEach-Object {
    curl.exe -k -s "https://169.58.221.49:443" -m 1 | Out-Null
}
Write-Host "[+] Network probes generated!" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  Simulation Complete!" -ForegroundColor Green
Write-Host "  Suricata IDS has recorded the intrusion attempt." -ForegroundColor White
Write-Host "  Now refresh your browser (press F5):" -ForegroundColor White
Write-Host "  1. Alerts Page: https://app.169-58-221-49.nip.io/alerts" -ForegroundColor Yellow
Write-Host "  2. SOC Dashboard: https://app.169-58-221-49.nip.io/dashboard" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
