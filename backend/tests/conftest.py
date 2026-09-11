import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["ENABLE_OTEL"] = "false"
os.environ["REDIS_HOST"] = "127.0.0.1"

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from main import app
from auth import verify_token

# Fake user — overrides real Keycloak JWT verification during tests
def fake_verify_token():
    return {"preferred_username": "test_user", "sub": "test-id", "realm_access": {"roles": ["analyst"]}}

app.dependency_overrides[verify_token] = fake_verify_token

@pytest.fixture(autouse=True)
def clean_redis_cache():
    from cache import redis_client
    try:
        redis_client.flushdb()
    except Exception:
        pass
    yield
    try:
        redis_client.flushdb()
    except Exception:
        pass

@pytest.fixture(autouse=True)
def mock_elasticsearch_indexing():
    """main.py `from search import index_document` karta hai, isliye main.py
    ke andar apni alag name-binding ban jaati hai — patch("search.index_document",...)
    us binding ko touch nahi karta. Isliye "main.index_document" patch karna zaroori hai."""
    with patch("main.index_document", return_value=None):
        yield
@pytest.fixture
def client():
    return TestClient(app)


# ── Reliability tests ke liye shared mocks ──

@pytest.fixture
def mock_all_threat_sources_clean():
    """Sab 4 threat-intel sources ko 'clean' response dene ke liye mock karta hai."""
    def fake_get(url, **kwargs):
        resp = MagicMock(status_code=200)
        if "virustotal" in url:
            resp.json.return_value = {"data": {"attributes": {"reputation": 10, "total_votes": {"malicious": 0}, "country": "US"}}}
        elif "abuseipdb" in url:
            resp.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        elif "alienvault" in url:
            resp.json.return_value = {"reputation": 0, "pulse_info": {"count": 0}, "country_name": "US"}
        elif "shodan" in url:
            resp.json.return_value = {"ports": [], "vulns": []}
        return resp
    with patch("resilience.requests.get", side_effect=fake_get):
        yield


@pytest.fixture
def mock_all_threat_sources_malicious():
    """Sab sources ko 'malicious' signal dene ke liye mock karta hai. Returns a dict
    so tests can do: patch("resilience.requests.get", **mock_all_threat_sources_malicious)"""
    def fake_get(url, **kwargs):
        resp = MagicMock(status_code=200)
        if "virustotal" in url:
            resp.json.return_value = {"data": {"attributes": {"reputation": -50, "total_votes": {"malicious": 20}, "country": "DE"}}}
        elif "abuseipdb" in url:
            resp.json.return_value = {"data": {"abuseConfidenceScore": 100, "totalReports": 500}}
        elif "alienvault" in url:
            resp.json.return_value = {"reputation": 0, "pulse_info": {"count": 20}, "country_name": "DE"}
        elif "shodan" in url:
            resp.json.return_value = {"ports": [22, 3389], "vulns": ["CVE-2021-1234"]}
        return resp
    return {"side_effect": fake_get}