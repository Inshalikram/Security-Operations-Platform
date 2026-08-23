from fastapi import FastAPI, Depends, Request, HTTPException
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
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
import json
import yara
import yaml
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge
from auth import verify_token_string

# ── OpenTelemetry tracing (exports to Tempo) ──
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sop_admin:changeme@127.0.0.1:5432/sop_db")

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
    country = Column(String, nullable=True)  # ── used by the Threat Map dashboard ──
    checked_at = Column(DateTime, default=datetime.utcnow)


# ── Asset inventory (for the frontend Assets page) ──
class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    ip_address = Column(String, index=True)
    asset_type = Column(String)          # server, workstation, network-device, etc.
    owner = Column(String)
    criticality = Column(String, default="medium")  # low, medium, high, critical
    status = Column(String, default="active")        # active, decommissioned
    created_at = Column(DateTime, default=datetime.utcnow)


# ── Organizations / tenants (for the frontend Organizations page) ──
class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ── Suricata alerts (model moved here so create_all() below actually creates this table) ──
class SuricataAlert(Base):
    __tablename__ = "suricata_alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    dest_ip = Column(String)
    signature = Column(String)
    severity = Column(Integer)
    raw_event = Column(JSON)


# ── Zeek notices (model here so create_all() below creates this table) ──
class ZeekNotice(Base):
    __tablename__ = "zeek_notices"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    note_type = Column(String)
    message = Column(String)
    src_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    raw_event = Column(JSON)


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Security Operations Platform API")
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Tracing setup — exports spans to Tempo over OTLP/gRPC ──
_otel_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://tempo:4317")
trace.set_tracer_provider(TracerProvider())
_tempo_exporter = OTLPSpanExporter(endpoint=_otel_endpoint, insecure=True)
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(_tempo_exporter))
FastAPIInstrumentor.instrument_app(app)

# ── Custom business metrics (beyond auto-tracked HTTP requests) ──
INCIDENTS_CREATED = Counter(
    'soc_incidents_created_total',
    'Total number of Hive incidents auto-created'
)
THREAT_VERDICTS = Counter(
    'soc_threat_verdicts_total',
    'Total threat verdicts by type',
    ['verdict']
)

# ── AI Gateway request tracking (for the "AI requests" dashboard) ──
AI_REQUESTS = Counter(
    'soc_ai_requests_total',
    'Total AI Gateway requests by provider and feature',
    ['provider', 'feature']
)
AI_REQUEST_FAILURES = Counter(
    'soc_ai_request_failures_total',
    'Total failed AI Gateway requests by provider and feature',
    ['provider', 'feature']
)

# ── Suricata alerts ingested counter (used by parse_suricata_alerts() below) ──
SURICATA_ALERTS_INGESTED = Counter(
    'soc_suricata_alerts_ingested_total',
    'Total Suricata alerts ingested into the platform'
)

# ── Queue size proxy: active WebSocket alert subscribers (for the "queue sizes" dashboard) ──
ACTIVE_WS_CONNECTIONS = Gauge(
    'soc_active_websocket_connections',
    'Current number of connected WebSocket alert clients'
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        ACTIVE_WS_CONNECTIONS.set(len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        ACTIVE_WS_CONNECTIONS.set(len(self.active_connections))

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://169.58.221.49:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_URL = os.getenv("THEHIVE_URL")


def call_ollama(prompt: str) -> str:
    try:
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        response = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": "llama3.2", "prompt": prompt, "stream": False},
            timeout=240
        )
        response.raise_for_status()
        data = response.json()
        print("OLLAMA RAW RESPONSE:", data)
        return data.get("response", "")
    except Exception as e:
        print("OLLAMA ERROR:", e)
        raise
# ── YARA — malware pattern scanning ──
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "yara", "suspicious_patterns.yar")
_yara_rules = None

def get_yara_rules():
    global _yara_rules
    if _yara_rules is None:
        _yara_rules = yara.compile(filepath=YARA_RULES_PATH)
    return _yara_rules

def scan_with_yara(data: bytes):
    rules = get_yara_rules()
    matches = rules.match(data=data)
    return [
        {
            "rule": m.rule,
            "severity": m.meta.get("severity", "unknown"),
            "description": m.meta.get("description", ""),
            "mitre_technique": m.meta.get("mitre_technique", "N/A"),
        }
        for m in matches
    ]

# ── Request model for the /yara/scan endpoint (this was missing — caused the startup crash) ──
class YaraScanRequest(BaseModel):
    content: str

SIGMA_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "sigma")

def load_sigma_rules():
    rules = []
    if not os.path.isdir(SIGMA_RULES_DIR):
        return rules
    for filename in os.listdir(SIGMA_RULES_DIR):
        if filename.endswith((".yml", ".yaml")):
            with open(os.path.join(SIGMA_RULES_DIR, filename), "r") as f:
                rules.append(yaml.safe_load(f))
    return rules

def evaluate_sigma_rules(log_event: dict):
    matched = []
    for rule in load_sigma_rules():
        selection = rule.get("detection", {}).get("selection", {})
        if all(log_event.get(k) == v for k, v in selection.items()):
            matched.append({
                "rule_title": rule.get("title"),
                "level": rule.get("level"),
                "tags": rule.get("tags", []),
                "description": rule.get("description")
            })
    return matched

class SigmaEvaluateRequest(BaseModel):
    log_event: dict


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

def call_ai(prompt: str, provider: str = None, feature: str = "generic") -> str:
    """The AI Gateway required by the assignment — routes to any of the 5 providers.
    `feature` labels which AI capability triggered the call (explain_ioc, executive_summary, etc.)
    so the Grafana 'AI requests' dashboard can break volume down per feature and per provider."""
    provider = (provider or AI_PROVIDER).lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown AI provider '{provider}'. Choose from: {list(PROVIDERS.keys())}")
    AI_REQUESTS.labels(provider=provider, feature=feature).inc()
    try:
        return PROVIDERS[provider](prompt)
    except Exception:
        AI_REQUEST_FAILURES.labels(provider=provider, feature=feature).inc()
        raise


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

API_KEYS = set(os.getenv("API_KEYS", "").split(","))

@app.get("/internal/verify-api-key")
def verify_api_key(request: Request):
    key = request.headers.get("X-API-Key")
    if not key or key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return {"status": "ok"}
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
            "malicious_votes": vt_malicious,
            "country": vt_attr.get("country")
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
            "pulse_count": pulse_count,
            "country": otx_resp.get("country_name")
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

    # ── Track detection rate by verdict type ──
    THREAT_VERDICTS.labels(verdict=result["overall_verdict"]).inc()

    # ── Pull a best-effort country for the Threat Map dashboard ──
    country = (
        result["details"].get("virustotal", {}).get("country")
        or result["details"].get("otx", {}).get("country")
    )

    # Save to database
    db = SessionLocal()
    new_record = Indicator(
        ip_address=ip_address,
        verdict=result["overall_verdict"],
        malicious_signals=result["malicious_signals"],
        sources_checked=result["sources_checked"],
        details=result["details"],
        country=country
    )
    db.add(new_record)
    db.commit()
    db.close()
    # Broadcast to WebSocket clients (fire-and-forget, safe even if no clients connected)
    try:
        import asyncio
        asyncio.run(manager.broadcast({
            "type": "new_alert",
            "ip": result["ip"],
            "verdict": result["overall_verdict"],
            "malicious_signals": result["malicious_signals"]
        }))
    except Exception:
        pass  # don't let broadcast failure break the main response

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
            # ── Track incident creation rate ──
            if hive_resp.status_code < 300:
                INCIDENTS_CREATED.inc()
        except Exception as e:
            result["thehive_case"] = {"error": str(e)}
    return result


# ── FIX: wrapped in try/except so ANY unexpected failure inside unified_threat_check
# (Keycloak timeout, DB drop, network glitch) returns a readable JSON error instead of
# an uncaught 500 with no detail. ──
@app.get("/threat-intel/check/{ip_address}")
def unified_threat_check_endpoint(ip_address: str, user=Depends(verify_token)):
    try:
        return unified_threat_check(ip_address)
    except Exception as e:
        return {"error": str(e)}


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
# NOTE: unified_threat_check(...) is now called INSIDE the try block in every endpoint below,
# so any failure there (Keycloak timeout, DB error, network glitch) returns a readable
# {"error": "..."} JSON response instead of an uncaught, detail-less 500.

@app.get("/ai/explain/{ip_address}")
def ai_explain_ioc(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
        threat_data = unified_threat_check(ip_address)
        prompt = f"""You are a SOC analyst assistant. Explain this threat intelligence finding in simple, clear language for a security report.

IP Address: {threat_data['ip']}
Overall Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}
Sources Checked: {', '.join(threat_data['sources_checked'])}
Details: {threat_data['details']}

Give a 3-4 sentence explanation of what this means and whether it's worth investigating."""
        return {"ip": ip_address, "verdict": threat_data["overall_verdict"], "ai_explanation": call_ai(prompt, provider, feature="explain_ioc")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/executive-summary/{ip_address}")
def ai_executive_summary(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
        threat_data = unified_threat_check(ip_address)
        prompt = f"""Write a short executive summary (max 5 sentences, no jargon) of this security finding for a non-technical manager.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Signals found: {threat_data['malicious_signals']}
Sources: {', '.join(threat_data['sources_checked'])}

Focus on business impact and whether immediate action is needed."""
        return {"ip": ip_address, "executive_summary": call_ai(prompt, provider, feature="executive_summary")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/mitre-map/{ip_address}")
def ai_mitre_map(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
        threat_data = unified_threat_check(ip_address)
        prompt = f"""Based on this threat intelligence data, suggest which MITRE ATT&CK tactics and techniques (with IDs, e.g. T1071) are most likely relevant. If there isn't enough data to map confidently, say so.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Details: {threat_data['details']}

Return a short bulleted list of technique ID + name + one-line justification."""
        return {"ip": ip_address, "mitre_mapping": call_ai(prompt, provider, feature="mitre_map")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/cve/{cve_id}")
def ai_cve_explain(cve_id: str, provider: str = None, user=Depends(verify_token)):
    prompt = f"""Explain {cve_id} in plain language for a SOC analyst: what it is, what's affected, how it's typically exploited, and its rough severity. If you're not certain of the exact details, say so rather than guessing specifics."""
    try:
        return {"cve": cve_id, "explanation": call_ai(prompt, provider, feature="cve_explain")}
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
        return {"input": payload.dict(), "ai_explanation": call_ai(prompt, provider, feature="malware_explain")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/recommend/{ip_address}")
def ai_incident_recommendation(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
        threat_data = unified_threat_check(ip_address)
        prompt = f"""Given this threat intel finding, recommend concrete SOC response actions (e.g. block IP, escalate, monitor, ignore) with brief justification.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}

Return a short numbered list of recommended actions, ordered by priority."""
        return {"ip": ip_address, "recommendations": call_ai(prompt, provider, feature="recommend")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/ai/threat-report/{ip_address}")
def ai_threat_report(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
        threat_data = unified_threat_check(ip_address)
        prompt = f"""Write a structured threat intelligence report for the following finding. Use these sections: Summary, Technical Details, MITRE ATT&CK Mapping, Recommended Actions.

IP: {threat_data['ip']}
Verdict: {threat_data['overall_verdict']}
Malicious Signals: {threat_data['malicious_signals']}
Sources Checked: {', '.join(threat_data['sources_checked'])}
Details: {threat_data['details']}"""
        return {"ip": ip_address, "report": call_ai(prompt, provider, feature="threat_report")}
    except Exception as e:
        return {"error": str(e)}


# ── RAG endpoint — combines current finding + this IP's own history from Postgres ──
@app.get("/ai/rag-explain/{ip_address}")
def ai_rag_explain(ip_address: str, provider: str = None, user=Depends(verify_token)):
    try:
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
        return {"ip": ip_address, "past_incidents_count": len(past_incidents), "ai_explanation": call_ai(prompt, provider, feature="rag_explain")}
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


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket, token: str = None):
    if not token:
        await websocket.close(code=1008, reason="Missing authentication token")
        return

    try:
        verify_token_string(token)
    except ValueError as e:
        await websocket.close(code=1008, reason=str(e))
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keeps connection alive, ignores client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/yara/scan")
def yara_scan(payload: YaraScanRequest, user=Depends(verify_token)):
    try:
        matches = scan_with_yara(payload.content.encode("utf-8"))
        return {
            "scanned_bytes": len(payload.content),
            "matches_found": len(matches),
            "matches": matches
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/sigma/evaluate")
def sigma_evaluate(payload: SigmaEvaluateRequest, user=Depends(verify_token)):
    matches = evaluate_sigma_rules(payload.log_event)
    return {"log_event": payload.log_event, "matched_rules": matches}

@app.get("/sigma/rules")
def list_sigma_rules(user=Depends(verify_token)):
    return load_sigma_rules()
# MISP_URL = os.getenv("MISP_URL")
# MISP_API_KEY = os.getenv("MISP_API_KEY")

# @app.get("/threat-intel/misp/{ip_address}")
# def check_ip_misp(ip_address: str, user=Depends(verify_token)):
#     headers = {
#         "Authorization": MISP_API_KEY,
#         "Accept": "application/json",
#         "Content-Type": "application/json"
#     }
#     payload = {"returnFormat": "json", "value": ip_address, "type": "ip-src"}
#     try:
#         response = requests.post(f"{MISP_URL}/attributes/restSearch", headers=headers, json=payload, timeout=15, verify=False)
#         data = response.json()
#         attributes = data.get("response", {}).get("Attribute", [])
#         return {
#             "ip": ip_address,
#             "matches_found": len(attributes),
#             "events": [{"event_id": a.get("event_id"), "category": a.get("category")} for a in attributes]
#         }
#     except Exception as e:
#         return {"error": str(e)}


# ── Suricata alert ingestion — model already defined above (near Base.metadata.create_all()) ──
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

def parse_suricata_alerts():
    """Reads Suricata's eve.json, extracts 'alert' events, saves new ones to DB.
    Only scans the most recent chunk of the file to avoid re-parsing a multi-MB
    file (and timing out the request) on every call."""
    if not os.path.exists(SURICATA_LOG_PATH):
        return {"error": "Suricata log file not found — is the suricata_logs volume mounted?"}

    db = SessionLocal()
    existing_count = db.query(SuricataAlert).count()
    new_alerts = 0

    MAX_LINES_TO_SCAN = 5000  # only look at the most recent chunk of the file

    with open(SURICATA_LOG_PATH, "r") as f:
        lines = f.readlines()[-MAX_LINES_TO_SCAN:]

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "alert":
            continue

        alert_data = event.get("alert", {})

        already_exists = db.query(SuricataAlert).filter(
            SuricataAlert.signature == alert_data.get("signature"),
            SuricataAlert.src_ip == event.get("src_ip"),
            SuricataAlert.dest_ip == event.get("dest_ip")
        ).first()
        if already_exists:
            continue

        record = SuricataAlert(
            timestamp=datetime.utcnow(),
            src_ip=event.get("src_ip"),
            dest_ip=event.get("dest_ip"),
            signature=alert_data.get("signature"),
            severity=alert_data.get("severity"),
            raw_event=event
        )
        db.add(record)
        new_alerts += 1
        SURICATA_ALERTS_INGESTED.inc()

    db.commit()
    db.close()
    return {"new_alerts_ingested": new_alerts, "total_alerts": existing_count + new_alerts}


@app.post("/security-monitoring/suricata/ingest")
def ingest_suricata_alerts(user=Depends(verify_token)):
    """Manually trigger ingestion of Suricata alerts from eve.json into the platform DB."""
    try:
        return parse_suricata_alerts()
    except Exception as e:
        return {"error": str(e)}


@app.get("/security-monitoring/suricata/alerts")
def get_suricata_alerts(user=Depends(verify_token)):
    """Return the most recent Suricata alerts stored in the platform."""
    db = SessionLocal()
    alerts = db.query(SuricataAlert).order_by(SuricataAlert.timestamp.desc()).limit(50).all()
    db.close()
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "src_ip": a.src_ip,
            "dest_ip": a.dest_ip,
            "signature": a.signature,
            "severity": a.severity
        } for a in alerts
    ]


# ── Wazuh integration — pulls manager health/status via Wazuh REST API ──
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "wazuh")

def get_wazuh_token():
    """Authenticates against Wazuh's API and returns a JWT token."""
    resp = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        verify=False,
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


@app.get("/security-monitoring/wazuh/status")
def wazuh_status(user=Depends(verify_token)):
    """Returns Wazuh manager health status — confirms the SIEM backend is reachable and running."""
    try:
        token = get_wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(f"{WAZUH_API_URL}/manager/status", headers=headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


@app.get("/security-monitoring/wazuh/agents")
def wazuh_agents(user=Depends(verify_token)):
    """Returns list of Wazuh-enrolled agents (empty if none enrolled yet)."""
    try:
        token = get_wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(f"{WAZUH_API_URL}/agents", headers=headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# ── Zeek notice ingestion — parses Zeek's TSV-format notice.log ──
ZEEK_NOTICE_LOG_PATH = "/var/log/zeek/notice.log"

def parse_zeek_notices():
    """Reads Zeek's notice.log (tab-separated with # header lines), extracts
    notable-traffic events, saves new ones to DB."""
    if not os.path.exists(ZEEK_NOTICE_LOG_PATH):
        return {"error": "Zeek notice.log not found — is the zeek_logs volume mounted?"}

    db = SessionLocal()
    existing_count = db.query(ZeekNotice).count()
    new_notices = 0

    fields = []
    with open(ZEEK_NOTICE_LOG_PATH, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue  # skip other header lines (#separator, #types, etc.)
            if not line.strip():
                continue

            values = line.split("\t")
            if len(values) != len(fields):
                continue  # malformed row, skip

            row = dict(zip(fields, values))

            note_type = row.get("note", "-")
            message = row.get("msg", "-")
            src_ip = row.get("id.orig_h", "-")
            dest_ip = row.get("id.resp_h", "-")

            already_exists = db.query(ZeekNotice).filter(
                ZeekNotice.note_type == note_type,
                ZeekNotice.message == message,
                ZeekNotice.src_ip == src_ip
            ).first()
            if already_exists:
                continue

            record = ZeekNotice(
                timestamp=datetime.utcnow(),
                note_type=note_type,
                message=message,
                src_ip=None if src_ip == "-" else src_ip,
                dest_ip=None if dest_ip == "-" else dest_ip,
                raw_event=row
            )
            db.add(record)
            new_notices += 1

    db.commit()
    db.close()
    return {"new_notices_ingested": new_notices, "total_notices": existing_count + new_notices}


@app.post("/security-monitoring/zeek/ingest")
def ingest_zeek_notices(user=Depends(verify_token)):
    """Manually trigger ingestion of Zeek notices from notice.log into the platform DB."""
    try:
        return parse_zeek_notices()
    except Exception as e:
        return {"error": str(e)}


@app.get("/security-monitoring/zeek/notices")
def get_zeek_notices(user=Depends(verify_token)):
    """Return the most recent Zeek notices stored in the platform."""
    db = SessionLocal()
    notices = db.query(ZeekNotice).order_by(ZeekNotice.timestamp.desc()).limit(50).all()
    db.close()
    return [
        {
            "id": n.id,
            "timestamp": n.timestamp.isoformat(),
            "note_type": n.note_type,
            "message": n.message,
            "src_ip": n.src_ip,
            "dest_ip": n.dest_ip
        } for n in notices
    ]


# ══════════════════════════════════════════════════════════════════════════
# CASE MANAGEMENT — list/view cases from TheHive (for the frontend Cases page)
# ══════════════════════════════════════════════════════════════════════════

@app.get("/cases")
def list_cases(user=Depends(verify_token)):
    """Returns recent TheHive cases, newest first. Frontend Cases page consumes this."""
    try:
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        # TheHive 5's Query API — lists all cases, sorted newest first.
        query_payload = {
            "query": [
                {"_name": "listCase"},
                {"_name": "sort", "_fields": [{"_createdAt": "desc"}]}
            ]
        }
        resp = requests.post(f"{THEHIVE_URL}/api/v1/query", json=query_payload, headers=headers, timeout=10)
        resp.raise_for_status()
        cases = resp.json()
        return {
            "count": len(cases),
            "cases": [
                {
                    "id": c.get("_id"),
                    "title": c.get("title"),
                    "severity": c.get("severity"),
                    "status": c.get("status"),
                    "tlp": c.get("tlp"),
                    "tags": c.get("tags", []),
                    "description": c.get("description"),
                    "created_at": c.get("_createdAt"),
                    "assignee": c.get("assignee")
                }
                for c in cases
            ]
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/cases/{case_id}")
def get_case_detail(case_id: str, user=Depends(verify_token)):
    """Returns full detail for a single TheHive case."""
    try:
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        resp = requests.get(f"{THEHIVE_URL}/api/v1/case/{case_id}", headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════
# THREAT MAP — country-aggregated verdicts (for the frontend Threat Map page)
# ══════════════════════════════════════════════════════════════════════════

@app.get("/threat-map")
def get_threat_map(user=Depends(verify_token)):
    try:
        db = SessionLocal()
        records = db.query(Indicator).order_by(Indicator.checked_at.desc()).limit(200).all()
        db.close()

        country_summary = {}
        points = []
        for r in records:
            country = r.country or "Unknown"
            if country not in country_summary:
                country_summary[country] = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}
            country_summary[country]["total"] += 1
            if r.verdict in country_summary[country]:
                country_summary[country][r.verdict] += 1
            points.append({
                "ip": r.ip_address,
                "country": country,
                "verdict": r.verdict,
                "malicious_signals": r.malicious_signals,
                "checked_at": r.checked_at.isoformat()
            })

        return {"countries": country_summary, "points": points}
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════
# ASSETS — simple asset inventory CRUD (for the frontend Assets page)
# ══════════════════════════════════════════════════════════════════════════

class AssetCreate(BaseModel):
    name: str
    ip_address: Optional[str] = None
    asset_type: Optional[str] = "server"
    owner: Optional[str] = None
    criticality: Optional[str] = "medium"

@app.get("/assets")
def list_assets(user=Depends(verify_token)):
    db = SessionLocal()
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    db.close()
    return [
        {
            "id": a.id, "name": a.name, "ip_address": a.ip_address,
            "asset_type": a.asset_type, "owner": a.owner,
            "criticality": a.criticality, "status": a.status,
            "created_at": a.created_at.isoformat()
        } for a in assets
    ]

@app.post("/assets")
def create_asset(payload: AssetCreate, user=Depends(verify_token)):
    db = SessionLocal()
    asset = Asset(**payload.dict())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.close()
    return {"id": asset.id, "message": "Asset created"}

@app.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, user=Depends(verify_token)):
    db = SessionLocal()
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        db.close()
        return {"error": "Asset not found"}
    db.delete(asset)
    db.commit()
    db.close()
    return {"message": "Asset deleted"}


# ══════════════════════════════════════════════════════════════════════════
# ORGANIZATIONS — simple tenant/org CRUD (for the frontend Organizations page)
# ══════════════════════════════════════════════════════════════════════════

class OrganizationCreate(BaseModel):
    name: str
    description: Optional[str] = None

@app.get("/organizations")
def list_organizations(user=Depends(verify_token)):
    db = SessionLocal()
    orgs = db.query(Organization).order_by(Organization.created_at.desc()).all()
    db.close()
    return [
        {"id": o.id, "name": o.name, "description": o.description, "created_at": o.created_at.isoformat()}
        for o in orgs
    ]

@app.post("/organizations")
def create_organization(payload: OrganizationCreate, user=Depends(verify_token)):
    db = SessionLocal()
    org = Organization(**payload.dict())
    db.add(org)
    db.commit()
    db.refresh(org)
    db.close()
    return {"id": org.id, "message": "Organization created"}

@app.delete("/organizations/{org_id}")
def delete_organization(org_id: int, user=Depends(verify_token)):
    db = SessionLocal()
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        db.close()
        return {"error": "Organization not found"}
    db.delete(org)
    db.commit()
    db.close()
    return {"message": "Organization deleted"}