from fastapi import FastAPI
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Security Operations Platform API")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

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