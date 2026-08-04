from fastapi import FastAPI
import os
import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_URL = os.getenv("THEHIVE_URL")

load_dotenv()

DATABASE_URL = "postgresql://sop_admin:changeme@localhost:5432/sop_db"

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

@app.get("/")
def root():
    return {"message": "SOC Platform Backend is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/threat-intel/ip/{ip_address}")
def check_ip(ip_address: str):
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
def check_ip_abuseipdb(ip_address: str):
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
def check_ip_otx(ip_address: str):
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
def check_domain_urlscan(domain: str):
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
def check_ip_shodan(ip_address: str):
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


@app.get("/threat-intel/check/{ip_address}")
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


@app.get("/threat-intel/history")
def get_history():
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