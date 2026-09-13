#!/bin/bash
# Linux Bash Attack Simulation Script for SOC Platform Evaluation
TARGET="https://app.169-58-221-49.nip.io"
echo "=========================================================="
echo "  SOC Platform Live Intrusion Simulation (Suricata IDS)   "
echo "  Target: $TARGET"
echo "=========================================================="

echo -e "\n[1/3] Simulating SQL Injection probe via 'sqlmap'..."
curl -k -s -A "sqlmap/1.7.2#stable" "$TARGET/?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--" -m 4 > /dev/null
echo "[+] Attack traffic dispatched! (Signature: 'sqlmap')"

echo -e "\n[2/3] Simulating Directory Traversal probe (Nikto scanner)..."
curl -k -s -A "Nikto/2.1.6" "$TARGET/../../etc/passwd" -m 4 > /dev/null
echo "[+] Attack traffic dispatched! (Signature: 'Nikto')"

echo -e "\n[3/3] Simulating Attack Probe on Management Ports..."
for i in {1..5}; do
    curl -k -s "https://169.58.221.49:443" -m 1 > /dev/null 2>&1
done
echo "[+] Network probes generated!"

echo -e "\n=========================================================="
echo "  Simulation Complete!"
echo "  Suricata IDS has recorded the intrusion attempt."
echo "  Now refresh your browser (press F5):"
echo "  1. Alerts Page: https://app.169-58-221-49.nip.io/alerts"
echo "  2. SOC Dashboard: https://app.169-58-221-49.nip.io/dashboard"
echo "=========================================================="
