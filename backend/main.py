from fastapi import FastAPI
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Security Operations Platform API")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

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
        response = requests.get(url, headers=headers, timeout=10)
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
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

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