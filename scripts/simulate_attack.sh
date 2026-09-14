#!/bin/bash
# Linux Bash Attack Simulation Script for SOC Platform Evaluation
# Dispatches plaintext HTTP and ICMP attack signatures directly to Suricata IDS on port 80

VPS_IP="169.58.221.49"
HTTP_TARGET="http://$VPS_IP"

echo "=========================================================="
echo "  SOC Platform Live Intrusion Simulation (Suricata IDS)   "
echo "  Target: $HTTP_TARGET (Plaintext Port 80 for NIDS DPI)   "
echo "=========================================================="

echo -e "\n[1/4] Simulating ICMP Ping sweep..."
ping -c 2 $VPS_IP > /dev/null 2>&1
echo "[+] ICMP echo packets dispatched! (Signature: 'ICMP Ping Detected')"

echo -e "\n[2/4] Simulating SQL Injection probe via 'sqlmap'..."
curl -s -A "sqlmap/1.7.2#stable" "$HTTP_TARGET/?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--" -m 3 > /dev/null 2>&1
echo "[+] SQLMap probe dispatched! (Signature: 'Suspicious User-Agent - sqlmap')"

echo -e "\n[3/4] Simulating Directory Traversal probe (Nikto scanner)..."
curl -s -A "Nikto/2.1.6" "$HTTP_TARGET/../../etc/passwd" -m 3 > /dev/null 2>&1
echo "[+] Nikto probe dispatched! (Signature: 'Nikto Web Scanner' & 'Directory Traversal')"

echo -e "\n[4/4] Simulating Port Scan burst (25 rapid probes to trip threshold)..."
for i in {1..25}; do
    curl -s "$HTTP_TARGET" -m 1 > /dev/null 2>&1
done
echo "[+] Port scan burst generated! (Signature: 'Possible Port Scan Detected')"

echo -e "\n=========================================================="
echo "  Simulation Complete!"
echo "  Suricata IDS has recorded the intrusion attempt."
echo "  Wait ~30-60 seconds for the backend watchdog cycle,"
echo "  then refresh your browser (press F5):"
echo "  1. Alerts Page: https://app.169-58-221-49.nip.io/alerts"
echo "  2. SOC Dashboard: https://app.169-58-221-49.nip.io/dashboard"
echo "=========================================================="
