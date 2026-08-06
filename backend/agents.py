from langgraph.graph import StateGraph, END
from typing import TypedDict, List
import requests
import os

# ── Agent State — what the agent carries between steps ──
class ThreatHuntState(TypedDict):
    ip_address: str
    findings: dict
    steps_taken: List[str]
    report: str

# ── Step 1: Query VirusTotal ──
def query_virustotal(state: ThreatHuntState) -> ThreatHuntState:
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{state['ip_address']}"
    try:
        resp = requests.get(url, headers=headers, timeout=10).json()
        attr = resp.get("data", {}).get("attributes", {})
        state["findings"]["virustotal"] = {
            "malicious_votes": attr.get("total_votes", {}).get("malicious", 0),
            "reputation": attr.get("reputation")
        }
    except Exception as e:
        state["findings"]["virustotal"] = {"error": str(e)}
    state["steps_taken"].append("Queried VirusTotal")
    return state

# ── Step 2: Query MISP (adjust to your MISP API setup) ──
def query_misp(state: ThreatHuntState) -> ThreatHuntState:
    try:
        misp_url = os.getenv("MISP_URL", "http://localhost:9004")
        misp_key = os.getenv("MISP_API_KEY")
        headers = {"Authorization": misp_key, "Accept": "application/json"}
        resp = requests.post(
            f"{misp_url}/attributes/restSearch",
            headers=headers,
            json={"value": state["ip_address"]},
            timeout=10,
            verify=False
        )
        data = resp.json()
        attributes = data.get("response", {}).get("Attribute", [])
        state["findings"]["misp"] = {"matches_found": len(attributes)}
    except Exception as e:
        state["findings"]["misp"] = {"error": str(e)}
    state["steps_taken"].append("Queried MISP")
    return state

# ── Step 3: Decide — is this worth deeper investigation? (agentic decision point) ──
def assess_and_decide(state: ThreatHuntState) -> str:
    vt = state["findings"].get("virustotal", {})
    malicious = vt.get("malicious_votes", 0) or 0
    if malicious > 0:
        state["steps_taken"].append("Decision: malicious signal found → generating report")
    else:
        state["steps_taken"].append("Decision: no strong signal → generating lightweight report")
    return "generate_report"

# ── Step 4: Generate final investigation report using the AI Gateway ──
def generate_report(state: ThreatHuntState) -> ThreatHuntState:
    from main import call_ai  # reuse your existing AI Gateway
    prompt = f"""You are an autonomous Threat Hunting Agent. You investigated IP {state['ip_address']} using the following steps:
{chr(10).join('- ' + s for s in state['steps_taken'])}

Findings:
{state['findings']}

Write a concise investigation report (Summary, Evidence, Verdict, Recommended Next Steps)."""
    from main import call_ai
    state["report"] = call_ai(prompt)
    return state

# ── Build the graph ──
def build_threat_hunting_agent():
    graph = StateGraph(ThreatHuntState)
    graph.add_node("query_virustotal", query_virustotal)
    graph.add_node("query_misp", query_misp)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("query_virustotal")
    graph.add_edge("query_virustotal", "query_misp")
    graph.add_edge("query_misp", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()

threat_hunting_agent = build_threat_hunting_agent()

def run_threat_hunt(ip_address: str):
    initial_state = {
        "ip_address": ip_address,
        "findings": {},
        "steps_taken": [],
        "report": ""
    }
    result = threat_hunting_agent.invoke(initial_state)
    return result
# ═══════════════════════════════════════════
# AGENT 2: Incident Triage Agent
# Classifies severity (Critical/High/Medium/Low) and auto-assigns
# ═══════════════════════════════════════════

class TriageState(TypedDict):
    ip_address: str
    threat_data: dict
    severity: str
    assigned_to: str
    reasoning: str

def gather_threat_data(state: TriageState) -> TriageState:
    from main import unified_threat_check
    state["threat_data"] = unified_threat_check(state["ip_address"])
    return state

def classify_severity(state: TriageState) -> TriageState:
    """Agentic decision node — the agent reasons about severity based on signals."""
    data = state["threat_data"]
    signals = data.get("malicious_signals", 0)
    verdict = data.get("overall_verdict", "unknown")

    if verdict == "malicious" and signals >= 3:
        state["severity"] = "Critical"
    elif verdict == "malicious":
        state["severity"] = "High"
    elif verdict == "suspicious":
        state["severity"] = "Medium"
    else:
        state["severity"] = "Low"
    return state

def auto_assign(state: TriageState) -> TriageState:
    """Agentic decision node — routes the incident based on severity."""
    routing = {
        "Critical": "senior-analyst-oncall",
        "High": "analyst-team-lead",
        "Medium": "analyst-queue",
        "Low": "automated-monitoring"
    }
    state["assigned_to"] = routing.get(state["severity"], "analyst-queue")
    return state

def generate_triage_reasoning(state: TriageState) -> TriageState:
    from main import call_ai
    prompt = f"""You are an autonomous Incident Triage Agent. You classified this incident and assigned it.

IP: {state['ip_address']}
Verdict: {state['threat_data'].get('overall_verdict')}
Malicious Signals: {state['threat_data'].get('malicious_signals')}
Assigned Severity: {state['severity']}
Assigned To: {state['assigned_to']}

Write a 2-3 sentence justification for this triage decision, as if logging it for an audit trail."""
    state["reasoning"] = call_ai(prompt)
    return state

def build_triage_agent():
    graph = StateGraph(TriageState)
    graph.add_node("gather_threat_data", gather_threat_data)
    graph.add_node("classify_severity", classify_severity)
    graph.add_node("auto_assign", auto_assign)
    graph.add_node("generate_triage_reasoning", generate_triage_reasoning)

    graph.set_entry_point("gather_threat_data")
    graph.add_edge("gather_threat_data", "classify_severity")
    graph.add_edge("classify_severity", "auto_assign")
    graph.add_edge("auto_assign", "generate_triage_reasoning")
    graph.add_edge("generate_triage_reasoning", END)

    return graph.compile()

triage_agent = build_triage_agent()

def run_triage(ip_address: str):
    initial_state = {
        "ip_address": ip_address,
        "threat_data": {},
        "severity": "",
        "assigned_to": "",
        "reasoning": ""
    }
    result = triage_agent.invoke(initial_state)
    return result
# ═══════════════════════════════════════════
# AGENT 3: Malware Investigation Agent
# Analyzes hashes/filenames/URLs and recommends containment
# ═══════════════════════════════════════════

class MalwareInvestigationState(TypedDict):
    file_hash: str
    filename: str
    url: str
    vt_findings: dict
    risk_level: str
    containment_recommendation: str

def query_vt_for_hash(state: MalwareInvestigationState) -> MalwareInvestigationState:
    """Agent decides what to query based on what evidence is available."""
    if not state.get("file_hash"):
        state["vt_findings"] = {"note": "No hash provided, skipped VirusTotal hash lookup"}
        return state
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    url = f"https://www.virustotal.com/api/v3/files/{state['file_hash']}"
    try:
        resp = requests.get(url, headers=headers, timeout=10).json()
        attr = resp.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        state["vt_findings"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "type_description": attr.get("type_description"),
            "names": attr.get("names", [])[:3]
        }
    except Exception as e:
        state["vt_findings"] = {"error": str(e)}
    return state

def assess_risk(state: MalwareInvestigationState) -> MalwareInvestigationState:
    """Agentic decision node — decide risk level from available evidence."""
    findings = state.get("vt_findings", {})
    malicious = findings.get("malicious", 0) or 0

    if malicious >= 10:
        state["risk_level"] = "Critical"
    elif malicious >= 3:
        state["risk_level"] = "High"
    elif malicious >= 1:
        state["risk_level"] = "Medium"
    else:
        state["risk_level"] = "Low"
    return state

def recommend_containment(state: MalwareInvestigationState) -> MalwareInvestigationState:
    from main import call_ai
    prompt = f"""You are an autonomous Malware Investigation Agent. Analyze this artifact and recommend containment actions.

Hash: {state.get('file_hash') or 'not provided'}
Filename: {state.get('filename') or 'not provided'}
URL: {state.get('url') or 'not provided'}
VirusTotal findings: {state['vt_findings']}
Assessed Risk Level: {state['risk_level']}

Write: 1) Brief analysis of what this artifact likely is, 2) A numbered list of concrete containment/response actions appropriate for this risk level."""
    state["containment_recommendation"] = call_ai(prompt)
    return state

def build_malware_agent():
    graph = StateGraph(MalwareInvestigationState)
    graph.add_node("query_vt_for_hash", query_vt_for_hash)
    graph.add_node("assess_risk", assess_risk)
    graph.add_node("recommend_containment", recommend_containment)

    graph.set_entry_point("query_vt_for_hash")
    graph.add_edge("query_vt_for_hash", "assess_risk")
    graph.add_edge("assess_risk", "recommend_containment")
    graph.add_edge("recommend_containment", END)

    return graph.compile()

malware_agent = build_malware_agent()

def run_malware_investigation(file_hash: str = None, filename: str = None, url: str = None):
    initial_state = {
        "file_hash": file_hash or "",
        "filename": filename or "",
        "url": url or "",
        "vt_findings": {},
        "risk_level": "",
        "containment_recommendation": ""
    }
    result = malware_agent.invoke(initial_state)
    return result


# ═══════════════════════════════════════════
# AGENT 4: Executive Reporting Agent
# Pulls recent incident history and generates a weekly/monthly/quarterly report
# ═══════════════════════════════════════════

class ExecReportState(TypedDict):
    period: str
    incidents: List[dict]
    stats: dict
    report: str

def gather_recent_incidents(state: ExecReportState) -> ExecReportState:
    from main import SessionLocal, Indicator
    from datetime import datetime, timedelta

    days_map = {"weekly": 7, "monthly": 30, "quarterly": 90}
    days = days_map.get(state["period"], 7)
    cutoff = datetime.utcnow() - timedelta(days=days)

    db = SessionLocal()
    records = db.query(Indicator).filter(Indicator.checked_at >= cutoff).order_by(Indicator.checked_at.desc()).all()
    db.close()

    state["incidents"] = [
        {
            "ip": r.ip_address,
            "verdict": r.verdict,
            "malicious_signals": r.malicious_signals,
            "checked_at": r.checked_at.isoformat()
        } for r in records
    ]
    return state

def compute_stats(state: ExecReportState) -> ExecReportState:
    """Agentic node — aggregates raw data into meaningful stats before handing to AI."""
    incidents = state["incidents"]
    total = len(incidents)
    malicious = sum(1 for i in incidents if i["verdict"] == "malicious")
    suspicious = sum(1 for i in incidents if i["verdict"] == "suspicious")
    clean = total - malicious - suspicious

    state["stats"] = {
        "total_checked": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean
    }
    return state

def generate_exec_report(state: ExecReportState) -> ExecReportState:
    from main import call_ai
    prompt = f"""You are an autonomous Executive Reporting Agent. Generate a {state['period']} security report for a non-technical executive audience.

Period: {state['period']}
Total indicators checked: {state['stats']['total_checked']}
Malicious findings: {state['stats']['malicious']}
Suspicious findings: {state['stats']['suspicious']}
Clean findings: {state['stats']['clean']}

Write a structured report with sections: Executive Summary, Key Metrics, Notable Incidents, Trend Assessment, Recommendations. Keep it business-focused, minimal jargon."""
    state["report"] = call_ai(prompt)
    return state

def build_exec_reporting_agent():
    graph = StateGraph(ExecReportState)
    graph.add_node("gather_recent_incidents", gather_recent_incidents)
    graph.add_node("compute_stats", compute_stats)
    graph.add_node("generate_exec_report", generate_exec_report)

    graph.set_entry_point("gather_recent_incidents")
    graph.add_edge("gather_recent_incidents", "compute_stats")
    graph.add_edge("compute_stats", "generate_exec_report")
    graph.add_edge("generate_exec_report", END)

    return graph.compile()

exec_reporting_agent = build_exec_reporting_agent()

def run_exec_report(period: str = "weekly"):
    initial_state = {
        "period": period,
        "incidents": [],
        "stats": {},
        "report": ""
    }
    result = exec_reporting_agent.invoke(initial_state)
    return result