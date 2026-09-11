"""
Ground-truth labeled evaluation dataset for RAG knowledge retrieval and generation.
Contains 18 benchmark test cases across Playbooks, MITRE ATT&CK, CVEs, and Sigma rules.
"""

RAG_EVAL_DATASET = [
    # ── Playbooks (5 cases) ──
    {
        "id": "rag_eval_01",
        "query": "What is the procedure for responding to a confirmed malicious IP detected in our network?",
        "category": "playbook",
        "expected_source_type": "playbook",
        "expected_chunk_titles": ["Malicious IP Response Playbook"],
        "expected_answer_facts": [
            "Confirm verdict via VirusTotal/AbuseIPDB/Shodan",
            "Block IP at firewall/Traefik",
            "Search Suricata/Zeek logs for related traffic",
            "Create TheHive case",
            "Notify SOC lead if >2 malicious signals"
        ],
    },
    {
        "id": "rag_eval_02",
        "query": "How should a SOC analyst contain a host infected with ransomware?",
        "category": "playbook",
        "expected_source_type": "playbook",
        "expected_chunk_titles": ["Ransomware Containment Playbook"],
        "expected_answer_facts": [
            "Isolate affected host from network immediately",
            "Identify ransomware family via file extension/ransom note",
            "Check backups are intact and offline",
            "Do not pay ransom without executive/legal approval",
            "Preserve disk image for forensics before rebuild"
        ],
    },
    {
        "id": "rag_eval_03",
        "query": "What steps should be taken when a user reports a suspicious phishing email?",
        "category": "playbook",
        "expected_source_type": "playbook",
        "expected_chunk_titles": ["Phishing Email Playbook"],
        "expected_answer_facts": [
            "Isolate reported email, extract IOCs",
            "Check hash/URL against VirusTotal and URLScan",
            "Block sender domain org-wide",
            "Check if any user interacted",
            "Force password reset if credentials may be compromised"
        ],
    },
    {
        "id": "rag_eval_04",
        "query": "What is the playbook for handling brute force and credential stuffing attacks?",
        "category": "playbook",
        "expected_source_type": "playbook",
        "expected_chunk_titles": ["Brute Force / Credential Stuffing Playbook"],
        "expected_answer_facts": [
            "Identify source IP(s) and targeted account(s) from failed-login logs",
            "Check AbuseIPDB/OTX for prior reports on the source IP",
            "Lock or force password reset on targeted accounts",
            "Block source IP at firewall if abuse confidence score is high",
            "Enable/verify MFA on all affected accounts"
        ],
    },
    {
        "id": "rag_eval_05",
        "query": "How do we investigate suspicious outbound command and control (C2) traffic?",
        "category": "playbook",
        "expected_source_type": "playbook",
        "expected_chunk_titles": ["Suspicious Outbound C2 Traffic Playbook"],
        "expected_answer_facts": [
            "Identify the internal host initiating the outbound connection",
            "Check destination IP/domain against threat intel",
            "Isolate the host from the network to stop further C2 communication",
            "Capture memory/disk image for forensics before remediation",
            "Hunt for the same destination IP/domain across all other hosts"
        ],
    },

    # ── MITRE ATT&CK Techniques (6 cases) ──
    {
        "id": "rag_eval_06",
        "query": "Which MITRE ATT&CK technique describes adversaries communicating over HTTP, DNS, or standard application layer protocols for C2?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1071 Application Layer Protocol"],
        "expected_answer_facts": [
            "T1071",
            "Application Layer Protocol",
            "communicate using OSI application layer protocols",
            "HTTP, DNS, or SMTP for C2"
        ],
    },
    {
        "id": "rag_eval_07",
        "query": "What MITRE technique involves adversaries dumping credentials from LSASS or SAM?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1003 OS Credential Dumping"],
        "expected_answer_facts": [
            "T1003",
            "OS Credential Dumping",
            "LSASS",
            "SAM",
            "obtain account login information"
        ],
    },
    {
        "id": "rag_eval_08",
        "query": "How does MITRE categorize active network scanning and IP block probing during reconnaissance?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1595 Active Scanning"],
        "expected_answer_facts": [
            "T1595",
            "Active Scanning",
            "probe victim infrastructure",
            "IP block scans",
            "reconnaissance"
        ],
    },
    {
        "id": "rag_eval_09",
        "query": "Which MITRE ATT&CK technique is associated with injecting malicious code into the address space of running processes?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1055 Process Injection"],
        "expected_answer_facts": [
            "T1055",
            "Process Injection",
            "inject code into processes",
            "evade defenses",
            "elevate privileges"
        ],
    },
    {
        "id": "rag_eval_10",
        "query": "What technique ID corresponds to adversaries purchasing or leasing servers and VPS infrastructure for attacks?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1583 Acquire Infrastructure"],
        "expected_answer_facts": [
            "T1583",
            "Acquire Infrastructure",
            "buy, lease, or rent infrastructure",
            "servers, domains, VPS",
            "attack platforms"
        ],
    },
    {
        "id": "rag_eval_11",
        "query": "Which MITRE technique describes attackers disabling or tampering with EDR, firewalls, and logging?",
        "category": "mitre",
        "expected_source_type": "mitre",
        "expected_chunk_titles": ["T1562 Impair Defenses"],
        "expected_answer_facts": [
            "T1562",
            "Impair Defenses",
            "disable or modify security tools",
            "EDR, firewall, logging",
            "avoid detection"
        ],
    },

    # ── CVE Vulnerabilities (5 cases) ──
    {
        "id": "rag_eval_12",
        "query": "What is CVE-2021-44228 Log4Shell and how does the vulnerability work?",
        "category": "cve",
        "expected_source_type": "cve",
        "expected_chunk_titles": ["CVE-2021-44228 Log4Shell"],
        "expected_answer_facts": [
            "CVE-2021-44228",
            "Log4Shell",
            "Apache Log4j2",
            "JNDI features",
            "LDAP/RMI endpoints",
            "remote code execution"
        ],
    },
    {
        "id": "rag_eval_13",
        "query": "Explain the Citrix Bleed vulnerability CVE-2023-4966 and its business impact.",
        "category": "cve",
        "expected_source_type": "cve",
        "expected_chunk_titles": ["CVE-2023-4966 Citrix Bleed"],
        "expected_answer_facts": [
            "CVE-2023-4966",
            "Citrix Bleed",
            "Citrix NetScaler ADC/Gateway",
            "buffer overflow",
            "session token theft",
            "authentication bypass"
        ],
    },
    {
        "id": "rag_eval_14",
        "query": "What was the XZ Utils backdoor identified as CVE-2024-3094?",
        "category": "cve",
        "expected_source_type": "cve",
        "expected_chunk_titles": ["CVE-2024-3094 XZ Utils Backdoor"],
        "expected_answer_facts": [
            "CVE-2024-3094",
            "XZ Utils Backdoor",
            "xz/liblzma library",
            "SSH authentication bypass",
            "Linux distributions"
        ],
    },
    {
        "id": "rag_eval_15",
        "query": "What vulnerability in MOVEit Transfer was exploited by the Cl0p ransomware gang (CVE-2023-34362)?",
        "category": "cve",
        "expected_source_type": "cve",
        "expected_chunk_titles": ["CVE-2023-34362 MOVEit Transfer SQL Injection"],
        "expected_answer_facts": [
            "CVE-2023-34362",
            "MOVEit Transfer",
            "SQL injection",
            "Cl0p ransomware",
            "database"
        ],
    },
    {
        "id": "rag_eval_16",
        "query": "Explain PrintNightmare CVE-2021-34527 in Windows Print Spooler.",
        "category": "cve",
        "expected_source_type": "cve",
        "expected_chunk_titles": ["CVE-2021-34527 PrintNightmare"],
        "expected_answer_facts": [
            "CVE-2021-34527",
            "PrintNightmare",
            "Windows Print Spooler",
            "remote code execution",
            "SYSTEM privileges"
        ],
    },

    # ── Sigma Detection Rules (2 cases) ──
    {
        "id": "rag_eval_17",
        "query": "Which Sigma detection rule alerts on multiple failed authentication attempts indicating brute force login attacks?",
        "category": "sigma_rule",
        "expected_source_type": "sigma_rule",
        "expected_chunk_titles": ["Multiple Failed Login Attempts (Brute Force)"],
        "expected_answer_facts": [
            "failed authentication attempts",
            "brute-force",
            "T1110",
            "failed_login"
        ],
    },
    {
        "id": "rag_eval_18",
        "query": "Which Sigma rule monitors network connections destined for known malicious IP addresses?",
        "category": "sigma_rule",
        "expected_source_type": "sigma_rule",
        "expected_chunk_titles": ["Suspicious Outbound Connection to Known Malicious IP"],
        "expected_answer_facts": [
            "outbound network connections",
            "flagged as malicious",
            "threat intelligence",
            "T1071"
        ],
    },
]
