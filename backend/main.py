from fastapi import FastAPI, Depends
import os
import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from auth import verify_token
from agents import run_threat_hunt, run_triage, run_malware_investigation, run_exec_report


load_dotenv()

DATABASE_URL = "postgresql://sop_admin:changeme@127.0.0.1:5432/sop_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    verdict = Column(String)
    malicious_signals = Column(Integer)
    sources_checked = Column(JSON)
    details = Column(JSON)
    checked_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Security Operations Platform API")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_URL = os.getenv("THEHIVE_URL")


def call_ollama(prompt: str) -> str:
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3.2", "prompt": prompt, "stream": False},
            timeout=120
        )
        response.raise_for_status()
        data = response.json()
        print("OLLAMA RAW RESPONSE:", data)
        return data.get("response", "")
    except Exception as e:
        print("OLLAMA ERROR:", e)
        raise


# ── AI GATEWAY — supports OpenAI, Gemini, Ollama, DeepSeek, Qwen ──
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")

def call_openai(prompt: str) -> str:
    headers = {"Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}", "Content-Type": "application/json"}
    payload = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]}
    r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def call_gemini(prompt: str) -> str:
    key = os.getenv("GEMINI_API_KEY")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    r = requests.post(url, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]

def call_deepseek(prompt: str) -> str:
    headers = {"Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}", "Content-Type": "application/json"}
    payload = {"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}]}
    r = requests.post("https://api.deepseek.com/chat/completions", headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

def call_qwen(prompt: str) -> str:
    headers = {"Authorization": f"Bearer {os.getenv('QWEN_API_KEY')}", "Content-Type": "application/json"}
    payload = {"model": "qwen-plus", "messages": [{"role": "user", "content": prompt}]}
    r = requests.post("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]

PROVIDERS = {
    "ollama": call_ollama,
    "openai": call_openai,
    "gemini": call_gemini,
    "deepseek": call_deepseek,
    "qwen": call_qwen,
}

def call_ai(prompt: str, provider: str = None) -> str:
    """The AI Gateway required by the assignment — routes to any of the 5 providers."""
    provider = (provider or AI_PROVIDER).lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown AI provider '{provider}'. Choose from: {list(PROVIDERS.keys())}")
    return PROVIDERS[provider](prompt)


@app.get("/")
def root():
    return {"message": "SOC Platform Backend is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}


# ── THREAT INTEL SOURCES (all now Keycloak-protected) ──

@app.get("/threat-intel/ip/{ip_address}")
def check_ip(ip_address: str, user=Depends(verify_token)):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "ip": ip_address,
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "malicious_votes": attributes.get("total_votes", {}).get("malicious"),
            "harmless_votes": attributes.get("total_votes", {}).get("harmless"),
            "last_analysis_stats": attributes.get("last_analysis_stats")
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.get("/threat-intel/abuseipdb/{ip_address}")
def check_ip_abuseipdb(ip_address: str, user=Depends(verify_token)):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json().get("data", {})
        return {
            "ip": ip_address,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "is_whitelisted": data.get("isWhitelisted")
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.get("/threat-intel/otx/{ip_address}")
def check_ip_otx(ip_address: str, user=Depends(verify_token)):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    try:
        response = requests.get(url, headers=headers, timeout=20)
        data = response.json()
        return {
            "ip": ip_address,
            "reputation": data.get("reputation"),
            "country": data.get("country_name"),
            "pulse_count": data.get("pulse_info", {}).get("count"),
            "asn": data.get("asn")
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.get("/threat-intel/urlscan/{domain}")
def check_domain_urlscan(domain: str, user=Depends(verify_token)):
    headers = {"API-Key": URLSCAN_API_KEY}
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        results = data.get("results", [])
        return {
            "domain": domain,
            "total_scans": data.get("total"),
            "recent_scans": [
                {
                    "url": r.get("page", {}).get("url"),
                    "date": r.get("task", {}).get("time"),
                    "malicious": r.get("verdicts", {}).get("overall", {}).get("malicious")
                } for r in results[:5]
            ]
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.get("/threat-intel/shodan/{ip_address}")
def check_ip_shodan(ip_address: str, user=Depends(verify_token)):
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        return {
            "ip": ip_address,
            "org": data.get("org"),
            "country": data.get("country_name"),
            "open_ports": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "vulns": list(data.get("vulns", []))
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── Internal function (NOT an endpoint) — reused by AI features, agents, and the protected endpoint below.
# Kept auth-free here because Depends() only works on HTTP-routed functions, not direct Python calls. ──
def unified_threat_check(ip_address: str):
    result = {
        "ip": ip_address,
        "sources_checked": [],
        "overall_verdict": "unknown",
        "malicious_signals": 0,
        "details": {}
    }

    # VirusTotal
    try:
        vt_headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        vt_resp = requests.get(vt_url, headers=vt_headers, timeout=10).json()
        vt_attr = vt_resp.get("data", {}).get("attributes", {})
        vt_malicious = vt_attr.get("total_votes", {}).get("malicious", 0)
        result["details"]["virustotal"] = {
            "reputation": vt_attr.get("reputation"),
            "malicious_votes": vt_malicious
        }
        result["sources_checked"].append("virustotal")
        if vt_malicious and vt_malicious > 0:
            result["malicious_signals"] += 1
    except Exception as e:
        result["details"]["virustotal"] = {"error": str(e)}

    # AbuseIPDB
    try:
        abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        abuse_params = {"ipAddress": ip_address, "maxAgeInDays": 90}
        abuse_resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=abuse_headers, params=abuse_params, timeout=10).json()
        abuse_data = abuse_resp.get("data", {})
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        result["details"]["abuseipdb"] = {
            "abuse_confidence_score": abuse_score,
            "total_reports": abuse_data.get("totalReports")
        }
        result["sources_checked"].append("abuseipdb")
        if abuse_score and abuse_score > 20:
            result["malicious_signals"] += 1
    except Exception as e:
        result["details"]["abuseipdb"] = {"error": str(e)}

    # OTX
    try:
        otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        otx_resp = requests.get(otx_url, headers=otx_headers, timeout=20).json()
        pulse_count = otx_resp.get("pulse_info", {}).get("count", 0)
        result["details"]["otx"] = {
            "reputation": otx_resp.get("reputation"),
            "pulse_count": pulse_count
        }
        result["sources_checked"].append("otx")
        if pulse_count and pulse_count > 0:
            result["malicious_signals"] += 1
    except Exception as e:
        result["details"]["otx"] = {"error": str(e)}

    # Shodan
    try:
        shodan_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
        shodan_resp = requests.get(shodan_url, timeout=10).json()
        vulns = list(shodan_resp.get("vulns", []))
        result["details"]["shodan"] = {
            "open_ports": shodan_resp.get("ports"),
            "vulns": vulns
        }
        result["sources_checked"].append("shodan")
        if vulns and len(vulns) > 0:
            result["malicious_signals"] += 1
    except Exception as e:
        result["details"]["shodan"] = {"error": str(e)}

    # Final verdict
    if result["malicious_signals"] >= 2:
        result["overall_verdict"] = "malicious"
    elif result["malicious_signals"] == 1:
        result["overall_verdict"] = "suspicious"
    else:
        result["overall_verdict"] = "clean"

    # Save to database
    db = SessionLocal()
    new_record = Indicator(
        ip_address=ip_address,
        verdict=result["overall_verdict"],
        malicious_signals=result["malicious_signals"],
        sources_checked=result["sources_checked"],
        details=result["details"]
    )
    db.add(new_record)
    db.commit()
    db.close()
    # Auto-create TheHive case if suspicious or malicious
    if result["overall_verdict"] in ["malicious", "suspicious"]:
        try:
            case_payload = {
                "title": f"Threat Alert: {ip_address} - {result['overall_verdict']}",
                "description": f"Automated detection.\nVerdict: {result['overall_verdict']}\nMalicious signals: {result['malicious_signals']}\nSources checked: {', '.join(result['sources_checked'])}",
                "severity": 3 if result["overall_verdict"] == "malicious" else 2,
                "tlp": 2,
                "tags": ["auto-generated", "threat-intel", result["overall_verdict"]]
            }
            hive_headers = {
                "Authorization": f"Bearer {THEHIVE_API_KEY}",
                "Content-Type": "application/json"
            }
            hive_resp = requests.post(
                f"{THEHIVE_URL}/api/v1/case",
                json=case_payload,
                headers=hive_headers,
                timeout=10
            )
            result["thehive_case"] = hive_resp.json() if hive_resp.status_code < 300 else {"error": hive_resp.text}
        except Exception as e:
            result["thehive_case"] = {"error": str(e)}
    return result


@app.get("/threat-intel/check/{ip_address}")
def unified_threat_check_endpoint(ip_address: str, user=Depends(verify_token)):
    return unified_threat_check(ip_address)


@app.get("/threat-intel/history")
def get_history(user=Depends(verify_token)):
    db = SessionLocal()
    records = db.query(Indicator).order_by(Indicator.checked_at.desc()).limit(20).all()
    db.close()
    return [
        {
            "ip": r.ip_address,
            "verdict": r.verdict,
            "malicious_signals": r.malicious_signals,
            "sources_checked": r.sources_checked,
            "checked_at": r.checked_at.isoformat()
        } for r in records
    ]


# ── RAG helper — pulls this IP's own history from Postgres to give the AI memory ──
def get_similar_past_incidents(ip_address: str, limit: int = 5):
    db = SessionLocal()
    records = db.query(Indicator).filter(
        Indicator.ip_address == ip_address
    ).order_by(Indicator.checked_at.desc()).limit(limit).all()
    db.close()
    return [
        {
            "verdict": r.verdict,
            "malicious_signals": r.malicious_signals,
            "checked_at": r.checked_at.isoformat()
        } for r in records
    ]


# ── AI FEATURES (all 7 required by the assignment, all going through call_ai, all Keycloak-protected) ──

@app.get("/ai/explain/{ip_address}")
def ai_explain_ioc(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    prompt = f"""You are a SOC analyst assistant. Explain this threat intelligence finding in simple, clear language for a security report.

IP Address: {threat_data['ip']}
Overall Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}
Sources Checked: {', '.join(threat_data['sources_checked'])}
Details: {threat_data['details']}

Give a 3-4 sentence explanation of what this means and whether it's worth investigating."""
    try:
        return {"ip": ip_address, "verdict": threat_data["overall_verdict"], "ai_explanation": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/executive-summary/{ip_address}")
def ai_executive_summary(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    prompt = f"""Write a short executive summary (max 5 sentences, no jargon) of this security finding for a non-technical manager.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Signals found: {threat_data['malicious_signals']}
Sources: {', '.join(threat_data['sources_checked'])}

Focus on business impact and whether immediate action is needed."""
    try:
        return {"ip": ip_address, "executive_summary": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/mitre-map/{ip_address}")
def ai_mitre_map(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    prompt = f"""Based on this threat intelligence data, suggest which MITRE ATT&CK tactics and techniques (with IDs, e.g. T1071) are most likely relevant. If there isn't enough data to map confidently, say so.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Details: {threat_data['details']}

Return a short bulleted list of technique ID + name + one-line justification."""
    try:
        return {"ip": ip_address, "mitre_mapping": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/cve/{cve_id}")
def ai_cve_explain(cve_id: str, provider: str = None, user=Depends(verify_token)):
    prompt = f"""Explain {cve_id} in plain language for a SOC analyst: what it is, what's affected, how it's typically exploited, and its rough severity. If you're not certain of the exact details, say so rather than guessing specifics."""
    try:
        return {"cve": cve_id, "explanation": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


class MalwareExplainRequest(BaseModel):
    hash: Optional[str] = None
    filename: Optional[str] = None
    url: Optional[str] = None


@app.post("/ai/malware-explain")
def ai_malware_explain(payload: MalwareExplainRequest, provider: str = None, user=Depends(verify_token)):
    prompt = f"""A SOC analyst is investigating a possible malware artifact. Explain what this likely is and recommend next investigation steps.

Hash: {payload.hash or 'not provided'}
Filename: {payload.filename or 'not provided'}
URL: {payload.url or 'not provided'}

Keep it to 4-5 sentences. Recommend concrete next steps (e.g. check VirusTotal, sandbox detonation, isolate host)."""
    try:
        return {"input": payload.dict(), "ai_explanation": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/recommend/{ip_address}")
def ai_incident_recommendation(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    prompt = f"""Given this threat intel finding, recommend concrete SOC response actions (e.g. block IP, escalate, monitor, ignore) with brief justification.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}

Return a short numbered list of recommended actions, ordered by priority."""
    try:
        return {"ip": ip_address, "recommendations": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/threat-report/{ip_address}")
def ai_threat_report(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    prompt = f"""Write a structured threat intelligence report for the following finding. Use these sections: Summary, Technical Details, MITRE ATT&CK Mapping, Recommended Actions.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}
Sources Checked: {', '.join(threat_data['sources_checked'])}
Details: {threat_data['details']}"""
    try:
        return {"ip": ip_address, "report": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


# ── RAG endpoint — combines current finding + this IP's own history from Postgres ──
@app.get("/ai/rag-explain/{ip_address}")
def ai_rag_explain(ip_address: str, provider: str = None, user=Depends(verify_token)):
    threat_data = unified_threat_check(ip_address)
    past_incidents = get_similar_past_incidents(ip_address)

    history_text = "No previous history found." if not past_incidents else "\n".join(
        [f"- {p['checked_at']}: verdict={p['verdict']}, signals={p['malicious_signals']}" for p in past_incidents]
    )

    prompt = f"""You are a SOC analyst assistant with access to historical data.

Current finding:
IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}

Past history for this IP:
{history_text}

Using both the current finding AND the past history, explain whether this is a recurring threat pattern and what that means for prioritization."""
    try:
        return {"ip": ip_address, "past_incidents_count": len(past_incidents), "ai_explanation": call_ai(prompt, provider)}
    except Exception as e:
        return {"error": str(e)}


# ── AGENTIC AI ENDPOINTS (4 autonomous LangGraph agents, all Keycloak-protected) ──

@app.get("/agents/threat-hunt/{ip_address}")
def threat_hunt_agent_endpoint(ip_address: str, user=Depends(verify_token)):
    try:
        result = run_threat_hunt(ip_address)
        return {
            "ip": result["ip_address"],
            "steps_taken": result["steps_taken"],
            "findings": result["findings"],
            "investigation_report": result["report"]
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/agents/triage/{ip_address}")
def triage_agent_endpoint(ip_address: str, user=Depends(verify_token)):
    try:
        result = run_triage(ip_address)
        return {
            "ip": result["ip_address"],
            "severity": result["severity"],
            "assigned_to": result["assigned_to"],
            "reasoning": result["reasoning"]
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/agents/malware-investigate")
def malware_agent_endpoint(payload: MalwareExplainRequest, user=Depends(verify_token)):
    try:
        result = run_malware_investigation(
            file_hash=payload.hash, filename=payload.filename, url=payload.url
        )
        return {
            "input": payload.dict(),
            "risk_level": result["risk_level"],
            "vt_findings": result["vt_findings"],
            "containment_recommendation": result["containment_recommendation"]
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/agents/exec-report/{period}")
def exec_report_agent_endpoint(period: str, user=Depends(verify_token)):
    if period not in ["weekly", "monthly", "quarterly"]:
        return {"error": "period must be one of: weekly, monthly, quarterly"}
    try:
        result = run_exec_report(period)
        return {
            "period": period,
            "stats": result["stats"],
            "report": result["report"]
        }
    except Exception as e:
        return {"error": str(e)}