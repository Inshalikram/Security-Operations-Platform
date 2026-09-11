"""Populates knowledge_chunks with Sigma rules, MITRE ATT&CK techniques, sample
CVEs, and org playbooks. Run once: python seed_knowledge.py
Safe to re-run — clears and re-seeds each source_type it touches."""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from main import Base, KnowledgeChunk, SessionLocal
from rag import embed_text
import yaml

SIGMA_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "sigma")

MITRE_TECHNIQUES = [
    {"id": "T1071", "name": "Application Layer Protocol", "desc": "Adversaries communicate using OSI application layer protocols to blend in with normal traffic, e.g. HTTP, DNS, or SMTP for C2."},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "desc": "Adversaries abuse command and script interpreters (PowerShell, bash, Python) to execute commands and payloads."},
    {"id": "T1055", "name": "Process Injection", "desc": "Adversaries inject code into processes to evade defenses and possibly elevate privileges."},
    {"id": "T1078", "name": "Valid Accounts", "desc": "Adversaries use compromised credentials to bypass access controls and blend in with legitimate activity."},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "desc": "Adversaries exploit weaknesses in internet-facing systems to gain initial access."},
    {"id": "T1566", "name": "Phishing", "desc": "Adversaries send phishing messages to gain access to victim systems, often with malicious attachments or links."},
    {"id": "T1486", "name": "Data Encrypted for Impact", "desc": "Adversaries encrypt data on target systems to interrupt availability, typically for ransomware."},
    {"id": "T1021", "name": "Remote Services", "desc": "Adversaries use valid accounts to log into services (RDP, SSH, VNC) accessible remotely for lateral movement."},
    {"id": "T1046", "name": "Network Service Discovery", "desc": "Adversaries scan a target network to gather information about running services, often as reconnaissance before exploitation — a common signature of scanning IPs flagged by AbuseIPDB/OTX."},
    {"id": "T1053", "name": "Scheduled Task/Job", "desc": "Adversaries abuse task scheduling functionality (cron, Task Scheduler) to execute code repeatedly or maintain persistence."},
    {"id": "T1105", "name": "Ingress Tool Transfer", "desc": "Adversaries transfer tools or files from an external system into a compromised environment, often via C2 channels."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "desc": "Adversaries encode, encrypt, or otherwise obfuscate files/data to evade detection by security tools."},
    {"id": "T1003", "name": "OS Credential Dumping", "desc": "Adversaries dump credentials from the OS (LSASS, SAM, /etc/shadow) to obtain account login information for reuse."},
    {"id": "T1110", "name": "Brute Force", "desc": "Adversaries use brute force techniques (password guessing, credential stuffing, password spraying) to gain access to accounts — commonly seen in high abuse-confidence AbuseIPDB reports."},
    {"id": "T1204", "name": "User Execution", "desc": "Adversaries rely on a user performing an action, like opening a malicious file or link, to gain execution."},
    {"id": "T1595", "name": "Active Scanning", "desc": "Adversaries actively probe victim infrastructure (IP block scans, vulnerability scans) as part of reconnaissance before an attack."},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "desc": "Adversaries steal data by exfiltrating it over an existing command and control channel rather than a separate channel."},
    {"id": "T1562", "name": "Impair Defenses", "desc": "Adversaries disable or modify security tools (EDR, firewall, logging) to avoid detection."},
    {"id": "T1036", "name": "Masquerading", "desc": "Adversaries disguise malicious files, processes, or traffic to appear legitimate and evade defenses."},
    {"id": "T1583", "name": "Acquire Infrastructure", "desc": "Adversaries buy, lease, or rent infrastructure (servers, domains, VPS) to use as attack platforms — often the origin of IPs later flagged as malicious in threat intel feeds."},
]

SAMPLE_CVES = [
    {"id": "CVE-2021-44228", "title": "Log4Shell", "desc": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/RMI endpoints, allowing remote code execution via crafted log messages."},
    {"id": "CVE-2023-23397", "title": "Outlook Elevation of Privilege", "desc": "Microsoft Outlook vulnerability allowing NTLM credential theft via a specially crafted email, no user interaction required."},
    {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "desc": "Malicious code injected into xz/liblzma library allowing SSH authentication bypass on affected Linux distributions."},
    {"id": "CVE-2023-34362", "title": "MOVEit Transfer SQL Injection", "desc": "SQL injection vulnerability in Progress MOVEit Transfer allowing unauthenticated attackers to access and modify the underlying database, exploited widely by the Cl0p ransomware group."},
    {"id": "CVE-2024-21762", "title": "Fortinet FortiOS Out-of-Bounds Write", "desc": "Out-of-bounds write vulnerability in FortiOS SSL VPN allowing unauthenticated remote code execution, actively exploited in the wild."},
    {"id": "CVE-2023-4966", "title": "Citrix Bleed", "desc": "Buffer overflow in Citrix NetScaler ADC/Gateway allowing session token theft and authentication bypass, enabling attackers to hijack legitimate user sessions."},
    {"id": "CVE-2022-30190", "title": "Follina", "desc": "Microsoft Support Diagnostic Tool (MSDT) remote code execution vulnerability triggered via malicious Office documents, exploitable without macros."},
    {"id": "CVE-2023-27350", "title": "PaperCut MF/NG Authentication Bypass", "desc": "Improper access control in PaperCut print management software allowing unauthenticated remote code execution, exploited by ransomware affiliates."},
    {"id": "CVE-2021-34527", "title": "PrintNightmare", "desc": "Windows Print Spooler remote code execution vulnerability allowing an authenticated attacker to run arbitrary code with SYSTEM privileges."},
]

PLAYBOOKS = [
    {"title": "Malicious IP Response Playbook", "content": "1. Confirm verdict via VirusTotal/AbuseIPDB/Shodan. 2. Block IP at firewall/Traefik. 3. Search Suricata/Zeek logs for related traffic. 4. Create TheHive case with severity based on signal count. 5. Notify SOC lead if >2 malicious signals."},
    {"title": "Phishing Email Playbook", "content": "1. Isolate reported email, extract IOCs (sender, URLs, attachment hash). 2. Check hash/URL against VirusTotal and URLScan. 3. Block sender domain org-wide. 4. Check if any user interacted (clicked link, opened attachment). 5. Force password reset if credentials may be compromised."},
    {"title": "Ransomware Containment Playbook", "content": "1. Isolate affected host from network immediately. 2. Identify ransomware family via file extension/ransom note. 3. Check backups are intact and offline. 4. Do not pay ransom without executive/legal approval. 5. Preserve disk image for forensics before rebuild."},
    {"title": "Brute Force / Credential Stuffing Playbook", "content": "1. Identify source IP(s) and targeted account(s) from failed-login logs. 2. Check AbuseIPDB/OTX for prior reports on the source IP. 3. Lock or force password reset on targeted accounts. 4. Block source IP at firewall if abuse confidence score is high. 5. Enable/verify MFA on all affected accounts."},
    {"title": "Suspicious Outbound C2 Traffic Playbook", "content": "1. Identify the internal host initiating the outbound connection. 2. Check destination IP/domain against threat intel (VirusTotal, OTX, Shodan). 3. Isolate the host from the network to stop further C2 communication. 4. Capture memory/disk image for forensics before remediation. 5. Hunt for the same destination IP/domain across all other hosts in the environment."},
]


def seed_sigma_rules(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "sigma_rule").delete()
    if not os.path.isdir(SIGMA_RULES_DIR):
        print("No sigma rules dir found, skipping")
        return
    for filename in os.listdir(SIGMA_RULES_DIR):
        if not filename.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(SIGMA_RULES_DIR, filename)) as f:
            rule = yaml.safe_load(f)
        text = f"Sigma rule: {rule.get('title', filename)}. {rule.get('description', '')}"
        emb = embed_text(text)
        db.add(KnowledgeChunk(source_type="sigma_rule", title=rule.get("title", filename), content=text, embedding=emb))
    db.commit()
    print("Seeded Sigma rules")


def seed_mitre(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "mitre").delete()
    for t in MITRE_TECHNIQUES:
        text = f"MITRE ATT&CK {t['id']} - {t['name']}: {t['desc']}"
        emb = embed_text(text)
        db.add(KnowledgeChunk(source_type="mitre", title=f"{t['id']} {t['name']}", content=text, embedding=emb))
    db.commit()
    print("Seeded MITRE ATT&CK techniques")


def seed_cves(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "cve").delete()
    for c in SAMPLE_CVES:
        text = f"{c['id']} ({c['title']}): {c['desc']}"
        emb = embed_text(text)
        db.add(KnowledgeChunk(source_type="cve", title=f"{c['id']} {c['title']}", content=text, embedding=emb))
    db.commit()
    print("Seeded sample CVEs")


def seed_playbooks(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "playbook").delete()
    for p in PLAYBOOKS:
        text = f"Playbook: {p['title']}. {p['content']}"
        emb = embed_text(text)
        db.add(KnowledgeChunk(source_type="playbook", title=p["title"], content=text, embedding=emb))
    db.commit()
    print("Seeded playbooks")


if __name__ == "__main__":
    db = SessionLocal()
    seed_sigma_rules(db)
    seed_mitre(db)
    seed_cves(db)
    seed_playbooks(db)
    db.close()
    print("Done seeding knowledge base.")