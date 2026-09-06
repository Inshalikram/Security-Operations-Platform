AI-Powered Security Operations Platform

A production-grade SOC (Security Operations Center) platform that unifies threat intelligence, real-time monitoring, and AI-driven investigation into a single operator console — built and deployed end-to-end as a 19-service Docker stack on a live VPS.

Overview

This platform integrates 10+ open-source security tools behind a FastAPI backend and a Next.js frontend, correlating signals from 5+ threat intelligence sources and automating case creation. On top of that, it layers a multi-provider AI Gateway with RAG-grounded explanations and 4 autonomous LangGraph agents that reason over live threat data — for threat hunting, incident triage, malware investigation, and executive reporting.

The system is fully deployed, monitored, and hardened: CI/CD with automated testing, secret scanning, container signing, and SBOM generation; full observability via Prometheus/Grafana/Loki/Tempo; and post-deployment security hardening (RBAC, firewall, credential/port lockdown, git-history remediation).

Key Features
Unified threat intelligence — real-time IP/IOC checks across VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, Shodan, and MISP, with automatic case creation in TheHive
AI Gateway — a single interface across 5 LLM providers (OpenAI, Gemini, DeepSeek, Qwen, Ollama) powering IOC explanations, executive summaries, MITRE ATT&CK mapping, CVE lookups, and recommendations
RAG-grounded analysis — retrieval over a 6-source knowledge base (Sigma rules, MITRE ATT&CK techniques, CVEs, org playbooks, past incidents) using Gemini embeddings and cosine similarity
4 autonomous LangGraph agents — Threat Hunting, Incident Triage, Malware Investigation, and Executive Reporting agents that reason over live data and produce actionable output
Real-time detection stack — Wazuh, Suricata, Zeek, and Falco feeding live alerts, with YARA and Sigma rule evaluation
Live alerting — WebSocket-based real-time alert broadcasting to the frontend on every threat check
Full-text search — Elasticsearch-backed search across indicators, Suricata alerts, and Zeek notices
Identity & access — Keycloak-based authentication and RBAC enforced across both backend (JWT verification) and frontend (NextAuth)
Observability — Prometheus + Grafana dashboards (API latency, request rate, AI Gateway usage, container health, threat verdict breakdown) with Loki/Tempo tracing
Automation — n8n workflows for operational automation, exported and version-controlled
Architecture
                        ┌──────────────────────┐
                        │   Next.js Frontend   │
                        │ (TypeScript, Tailwind,│
                        │   Shadcn UI, NextAuth)│
                        └──────────┬───────────┘
                                   │  Traefik (reverse proxy / TLS)
                        ┌──────────▼───────────┐
                        │   FastAPI Backend     │
                        │ (SQLAlchemy, Pydantic,│
                        │   JWT auth via jose)  │
                        └──┬───────┬────────┬───┘
                           │       │        │
              ┌────────────┘       │        └────────────┐
              ▼                    ▼                     ▼
     ┌─────────────────┐  ┌───────────────┐   ┌────────────────────┐
     │  AI Gateway      │  │ Detection      │   │ Threat Intel /      │
     │  (5 providers +  │  │ Stack (Wazuh,  │   │ Case Mgmt (VT,      │
     │  RAG + 4 LangGraph│  │ Suricata, Zeek,│   │ AbuseIPDB, OTX,     │
     │  agents)         │  │ Falco, YARA,   │   │ Shodan, MISP,       │
     │                  │  │ Sigma)         │   │ TheHive, n8n)        │
     └─────────────────┘  └───────────────┘   └────────────────────┘
              │                    │                     │
              └────────────┬───────┴──────────┬──────────┘
                            ▼                  ▼
                  ┌──────────────────┐ ┌──────────────────┐
                  │ PostgreSQL, Redis,│ │  Observability    │
                  │ Elasticsearch,    │ │ (Prometheus,      │
                  │ MinIO             │ │  Grafana, Loki,   │
                  └──────────────────┘ │  Tempo, cAdvisor)  │
                                        └──────────────────┘

Deployed as a 19-service Docker Compose stack on a Linux VPS, provisioned via Terraform, sitting behind Traefik with TLS.

Tech Stack
Category	Tools
Security Monitoring	Wazuh, Suricata, Zeek, Falco, YARA, Sigma
Threat Intelligence	VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, Shodan, MISP
Case Management & Automation	TheHive, n8n
Authentication & API Gateway	Keycloak, Traefik
AI / LLM Providers	OpenAI, Google Gemini, DeepSeek, Qwen, Ollama
AI Frameworks	LangGraph (autonomous agents), Gemini Embeddings (RAG)
Backend	Python, FastAPI, SQLAlchemy, Pydantic, python-jose (JWT)
Frontend	Next.js, React, TypeScript, TailwindCSS, Shadcn UI, NextAuth
Databases & Storage	PostgreSQL, Redis, Elasticsearch, MinIO
Observability	Prometheus, Grafana, Loki, Promtail, Tempo, OpenTelemetry, cAdvisor
Containerization & DevOps	Docker, Docker Compose, GitHub Actions
CI/CD Security	Gitleaks, Trivy, Bandit, Syft (SBOM), OWASP Dependency-Check, Cosign
Infrastructure as Code	Terraform (Contabo + OVH providers)
CI/CD & Security Hardening

Every push runs through a GitHub Actions pipeline covering:

Automated test suite (pytest — health, auth, threat intel, YARA, Sigma, AI Gateway, organizations)
Secret scanning (Gitleaks)
Static analysis (Bandit) and dependency vulnerability scanning (Trivy, OWASP Dependency-Check)
Software Bill of Materials generation (Syft)
Container image signing (Cosign)

Post-deployment hardening includes RBAC enforcement across all protected endpoints, firewall configuration (UFW), credential and port lockdown, and git-history remediation.

Validation
26-test automated suite covering core endpoints, authentication, threat intelligence, detection rule evaluation, and the AI Gateway
Live-traffic monitoring — validated against real internet traffic on the deployed VPS (live Suricata alerts, Zeek connection logs, and port-scan detections from real external IPs)
End-to-end verified flows: login → dashboard → live threat search → AI-powered explanation → automatic case creation, all confirmed working on the live deployment
Status

Live deployment, full observability stack, CI/CD pipeline, and documentation (architecture, API, deployment, disaster recovery, and hardening guides) are complete.


Inshal Ikram
LinkedIn · inshalikram06@gmail.com# Security-Operations-Platform
