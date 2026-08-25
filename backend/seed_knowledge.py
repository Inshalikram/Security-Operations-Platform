"""Populates knowledge_chunks with Sigma rules, MITRE ATT&CK techniques, sample
CVEs, and org playbooks. Run once: python seed_knowledge.py
Safe to re-run — clears and re-seeds each source_type it touches."""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Base, KnowledgeChunk
from rag import embed_text
import yaml

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sop_admin:changeme@postgres:5432/sop_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(bind=engine)

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
]

SAMPLE_CVES = [
    {"id": "CVE-2021-44228", "title": "Log4Shell", "desc": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/RMI endpoints, allowing remote code execution via crafted log messages."},
    {"id": "CVE-2023-23397", "title": "Outlook Elevation of Privilege", "desc": "Microsoft Outlook vulnerability allowing NTLM credential theft via a specially crafted email, no user interaction required."},
    {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "desc": "Malicious code injected into xz/liblzma library allowing SSH authentication bypass on affected Linux distributions."},
]

PLAYBOOKS = [
    {"title": "Malicious IP Response Playbook", "content": "1. Confirm verdict via VirusTotal/AbuseIPDB/Shodan. 2. Block IP at firewall/Traefik. 3. Search Suricata/Zeek logs for related traffic. 4. Create TheHive case with severity based on signal count. 5. Notify SOC lead if >2 malicious signals."},
    {"title": "Phishing Email Playbook", "content": "1. Isolate reported email, extract IOCs (sender, URLs, attachment hash). 2. Check hash/URL against VirusTotal and URLScan. 3. Block sender domain org-wide. 4. Check if any user interacted (clicked link, opened attachment). 5. Force password reset if credentials may be compromised."},
    {"title": "Ransomware Containment Playbook", "content": "1. Isolate affected host from network immediately. 2. Identify ransomware family via file extension/ransom note. 3. Check backups are intact and offline. 4. Do not pay ransom without executive/legal approval. 5. Preserve disk image for forensics before rebuild."},
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
        if emb:
            db.add(KnowledgeChunk(source_type="sigma_rule", title=rule.get("title", filename), content=text, embedding=emb))
    db.commit()
    print("Seeded Sigma rules")


def seed_mitre(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "mitre").delete()
    for t in MITRE_TECHNIQUES:
        text = f"MITRE ATT&CK {t['id']} - {t['name']}: {t['desc']}"
        emb = embed_text(text)
        if emb:
            db.add(KnowledgeChunk(source_type="mitre", title=f"{t['id']} {t['name']}", content=text, embedding=emb))
    db.commit()
    print("Seeded MITRE ATT&CK techniques")


def seed_cves(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "cve").delete()
    for c in SAMPLE_CVES:
        text = f"{c['id']} ({c['title']}): {c['desc']}"
        emb = embed_text(text)
        if emb:
            db.add(KnowledgeChunk(source_type="cve", title=f"{c['id']} {c['title']}", content=text, embedding=emb))
    db.commit()
    print("Seeded sample CVEs")


def seed_playbooks(db):
    db.query(KnowledgeChunk).filter(KnowledgeChunk.source_type == "playbook").delete()
    for p in PLAYBOOKS:
        text = f"Playbook: {p['title']}. {p['content']}"
        emb = embed_text(text)
        if emb:
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