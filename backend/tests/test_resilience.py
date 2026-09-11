"""
Reliability tests — simulates each failure scenario from the assignment
and asserts the system degrades gracefully instead of crashing.
"""
import time
import pytest
from unittest.mock import patch, MagicMock
import requests

import main
from resilience import get_breaker, _breakers


@pytest.fixture(autouse=True)
def reset_circuit_breakers():
    """Har test se pehle circuit breakers reset karo taake ek test ka
    failure count doosre test ko affect na kare."""
    _breakers.clear()
    yield
    _breakers.clear()


# ── 1. Postgres unavailable ──
def test_health_degraded_when_postgres_down(client):
    with patch("main.SessionLocal") as mock_session:
        mock_session.side_effect = Exception("connection refused")
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert "down" in data["checks"]["database"]


# ── 2. Redis unavailable ──
def test_health_degraded_when_redis_down(client):
    with patch("cache.redis_client.ping", side_effect=Exception("connection refused")):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert "down" in data["checks"]["redis"]


def test_threat_check_survives_redis_down(client, mock_all_threat_sources_clean):
    """Redis pura down ho to bhi threat-check crash nahi hona chahiye —
    cache.py already fail-safe hai (returns None instead of raising)."""
    with patch("cache.redis_client.get", side_effect=Exception("connection refused")), \
         patch("cache.redis_client.setex", side_effect=Exception("connection refused")):
        response = client.get("/threat-intel/check/1.2.3.4")
        assert response.status_code == 200
        data = response.json()
        assert "overall_verdict" in data  # crash nahi hua, result mila


# ── 3. Threat-intel API timeout + retry/backoff ──
def test_threat_intel_timeout_triggers_retries_then_graceful_error(client):
    """VirusTotal hamesha timeout de to retries chalni chahiye, phir
    result mein 'timeout' error aana chahiye, crash nahi."""
    with patch("requests.get", side_effect=requests.exceptions.Timeout("simulated timeout")):
        start = time.time()
        response = client.get("/threat-intel/check/5.6.7.8")
        elapsed = time.time() - start

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "unknown"  # koi source succeed nahi hua
        assert "virustotal" in data["sources_failed"]
        assert "timeout" in data["details"]["virustotal"]["error"]
        # backoff se kam se kam 0.5+1+2 = 3.5s se zyada lagna chahiye
        # (4 sources x 3 attempts each, but sources run sequentially in current code)
        assert elapsed > 0.4  # loose bound, sirf confirm karo ke retry hui, turant fail nahi hua


# ── 4. Circuit breaker opens after repeated failures ──
def test_circuit_breaker_opens_after_threshold():
    """Directly resilience.resilient_request() ko test karta hai — poore
    FastAPI app/endpoint ke through nahi jaata. Ye isliye zaroori hai kyunki
    main.py ka background monitoring_watchdog() (Wazuh/Elasticsearch se
    connect karne ki koshish, real DNS failures ke saath) is dev machine pe
    GIL contention create karta hai jo foreground synchronous requests ko
    randomly slow kar deta hai — us noise ko bypass karke sirf circuit
    breaker logic ko directly, reliably test karte hain."""
    from resilience import resilient_request, get_breaker

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("down")):
        for _ in range(5):
            try:
                resilient_request("virustotal", "GET", "https://www.virustotal.com/x",
                                   max_attempts=3, timeout=1,
                                   failure_threshold=5, recovery_timeout=60)
            except Exception:
                pass  # expected — har call fail hogi

        breaker = get_breaker("virustotal")
        assert breaker.state == "open"

        # Ab agli call turant fail honi chahiye, retries ke bina
        start = time.time()
        with pytest.raises(RuntimeError, match="circuit_open"):
            resilient_request("virustotal", "GET", "https://www.virustotal.com/x",
                               max_attempts=3, timeout=1,
                               failure_threshold=5, recovery_timeout=60)
        elapsed = time.time() - start
        assert elapsed < 1.0


# ── 5. TheHive unavailable → dead-letter queue ──
def test_thehive_down_queues_to_dlq_not_lost(client, mock_all_threat_sources_malicious):
    """TheHive down ho to case create fail ho, lekin verdict phir bhi
    mile aur failed case DLQ mein chala jaye (drop na ho)."""
    with patch("resilience.requests.get", **mock_all_threat_sources_malicious), \
         patch("resilience.requests.post", side_effect=requests.exceptions.ConnectionError("thehive down")):
        response = client.get("/threat-intel/check/8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] in ("malicious", "suspicious")
        assert data["thehive_case"].get("queued_for_retry") is True

    # DLQ mein entry bani honi chahiye
    dlq_response = client.get("/admin/dlq")
    assert dlq_response.status_code == 200
    dlq_entries = dlq_response.json()
    assert any(e["service"] == "thehive" for e in dlq_entries)


# ── 6. Elasticsearch unavailable — best-effort, never breaks the endpoint ──
def test_elasticsearch_down_does_not_break_threat_check(client, mock_all_threat_sources_clean):
    with patch("search.index_document", side_effect=Exception("ES connection refused")):
        response = client.get("/threat-intel/check/2.2.2.2")
        assert response.status_code == 200
        assert "overall_verdict" in response.json()


# ── 7. AI provider timeout → fallback chain ──
def test_ai_provider_fallback_on_timeout():
    """PROVIDERS dict function OBJECTS ko capture karta hai import time pe,
    isliye patch("main.call_ollama",...) kaam nahi karta — PROVIDERS dict ki
    entries seedha patch karni hoti hain."""
    fail_ollama = MagicMock(side_effect=requests.exceptions.Timeout("ollama down"))
    fallback_openai = MagicMock(return_value="fallback response from openai")
    with patch.dict(main.PROVIDERS, {"ollama": fail_ollama, "openai": fallback_openai}):
        result = main.call_ai("test prompt", provider="ollama", feature="test")
        assert result == "fallback response from openai"


def test_ai_all_providers_fail_raises_clear_error():
    failing = MagicMock(side_effect=Exception("down"))
    with patch.dict(main.PROVIDERS, {k: failing for k in main.PROVIDERS}):
        with pytest.raises(RuntimeError, match="all AI providers failed"):
            main.call_ai("test prompt", provider="ollama", feature="test")


def test_idempotency_lock_suppresses_duplicate_case():
    """Real Redis pe depend nahi karta — SETNX behavior ko in-memory
    dict se simulate karta hai."""
    from cache import acquire_lock
    store = {}

    def fake_set(key, value, nx=False, ex=None):
        if nx and key in store:
            return None  # key already exists — SETNX fails
        store[key] = value
        return True

    with patch("cache.redis_client.set", side_effect=fake_set):
        lock_key = "case_lock:7.7.7.7:malicious"
        assert acquire_lock(lock_key, ttl_seconds=300) is True   # pehli baar lock milta hai
        assert acquire_lock(lock_key, ttl_seconds=300) is False  # doosri baar duplicate detect hota hai


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: RELIABILITY / GRACEFUL DEGRADATION TESTS
# ══════════════════════════════════════════════════════════════════════════

def test_threat_intel_partial_failure_single_source(client):
    """When VirusTotal fails/timeouts but AbuseIPDB/OTX/Shodan succeed,
    response must return HTTP 200 with degraded: True and unavailable_sources: ['virustotal']."""
    def fake_get(url, **kwargs):
        if "virustotal.com" in url:
            raise requests.exceptions.Timeout("VT timeout")
        resp = MagicMock(status_code=200)
        if "abuseipdb.com" in url:
            resp.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        elif "alienvault.com" in url:
            resp.json.return_value = {"reputation": 0, "pulse_info": {"count": 0}, "country_name": "US"}
        elif "shodan.io" in url:
            resp.json.return_value = {"ports": [], "vulns": []}
        return resp

    with patch("resilience.requests.get", side_effect=fake_get):
        response = client.get("/threat-intel/check/9.9.9.9")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert "virustotal" in data["unavailable_sources"]
        assert set(data["sources_checked"]) == {"abuseipdb", "otx", "shodan"}
        assert data["overall_verdict"] == "clean"
        assert "timeout" in data["details"]["virustotal"]["error"]


def test_threat_intel_partial_failure_multiple_sources(client):
    """When 2 sources fail, the surviving sources are still aggregated."""
    def fake_get(url, **kwargs):
        if "virustotal.com" in url:
            raise requests.exceptions.ConnectionError("VT down")
        if "abuseipdb.com" in url:
            raise requests.exceptions.HTTPError("AbuseIPDB 503", response=MagicMock(status_code=503))
        resp = MagicMock(status_code=200)
        if "alienvault.com" in url:
            resp.json.return_value = {"reputation": -10, "pulse_info": {"count": 10}, "country_name": "RU"}
        elif "shodan.io" in url:
            resp.json.return_value = {"ports": [22], "vulns": []}
        return resp

    with patch("resilience.requests.get", side_effect=fake_get):
        response = client.get("/threat-intel/check/9.9.9.8")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert set(data["unavailable_sources"]) == {"virustotal", "abuseipdb"}
        assert set(data["sources_checked"]) == {"otx", "shodan"}
        assert data["overall_verdict"] in ["suspicious", "malicious"]


def test_threat_intel_all_sources_down_returns_unknown_not_500(client):
    """When ALL sources fail, response is 200 (never 500), verdict is 'unknown', degraded is True."""
    with patch("resilience.requests.get", side_effect=requests.exceptions.ConnectionError("network down")):
        response = client.get("/threat-intel/check/9.9.9.7")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert len(data["unavailable_sources"]) == 4
        assert data["sources_checked"] == []
        assert data["overall_verdict"] == "unknown"
        assert data["malicious_signals"] == 0


def test_search_falls_back_to_postgres_when_elasticsearch_fails(client):
    """When Elasticsearch search fails or cluster is down, /search falls back to PostgreSQL."""
    payload = {
        "name": "resilience-search-asset",
        "ip_address": "10.99.99.99",
        "asset_type": "server",
        "criticality": "high"
    }
    create_resp = client.post("/assets", json=payload)
    assert create_resp.status_code == 200

    with patch("main.search_all", return_value=None):
        response = client.get("/search?q=resilience-search-asset")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert data["source"] == "postgresql_fallback"
        assert any(r.get("name") == "resilience-search-asset" for r in data["results"])


def test_ai_explain_degraded_fallback_when_providers_down(client, mock_all_threat_sources_clean):
    failing = MagicMock(side_effect=RuntimeError("all AI providers failed"))
    with patch("main.call_ai", failing):
        response = client.get("/ai/explain/1.2.3.4")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert data["fallback"] is True
        assert "DEGRADED MODE" in data["ai_explanation"]


def test_ai_executive_summary_degraded_fallback_when_providers_down(client, mock_all_threat_sources_clean):
    failing = MagicMock(side_effect=RuntimeError("all AI providers failed"))
    with patch("main.call_ai", failing):
        response = client.get("/ai/executive-summary/1.2.3.4")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert data["fallback"] is True
        assert "DEGRADED MODE" in data["executive_summary"]


def test_ai_recommendations_degraded_fallback_when_providers_down(client, mock_all_threat_sources_clean):
    failing = MagicMock(side_effect=RuntimeError("all AI providers failed"))
    with patch("main.call_ai", failing):
        response = client.get("/ai/recommend/1.2.3.4")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert data["fallback"] is True
        assert "recommendations" in data


def test_ai_cve_explain_degraded_fallback_when_providers_down(client):
    failing = MagicMock(side_effect=RuntimeError("all AI providers failed"))
    with patch("main.call_ai", failing):
        response = client.get("/ai/cve/CVE-2024-9999")
        assert response.status_code == 200
        data = response.json()
        assert data["degraded"] is True
        assert data["fallback"] is True
        assert "DEGRADED MODE" in data["explanation"]
        assert "NVD" in data["explanation"]


def test_resilient_call_retries_and_trips_breaker():
    from resilience import resilient_call, get_breaker
    mock_func = MagicMock(side_effect=ValueError("connection broken"))

    for _ in range(3):
        try:
            resilient_call("test_svc", mock_func, max_attempts=2, failure_threshold=3, recovery_timeout=60)
        except Exception:
            pass

    breaker = get_breaker("test_svc")
    assert breaker.state == "open"

    with pytest.raises(RuntimeError, match="circuit_open"):
        resilient_call("test_svc", mock_func, max_attempts=2, failure_threshold=3, recovery_timeout=60)


def test_dlq_replay_for_elasticsearch_events(client):
    from main import SessionLocal, DeadLetterEvent
    db = SessionLocal()
    event = DeadLetterEvent(service="elasticsearch", payload={"index": "threat_indicators", "id": 1, "body": {"test": "data"}}, error="ES connection timeout")
    db.add(event)
    db.commit()
    event_id = event.id
    db.close()

    with patch("main.index_document", return_value=None):
        response = client.post(f"/admin/dlq/{event_id}/retry")
        assert response.status_code == 200
        data = response.json()
        assert data["retried"] == "success"
        assert data["service"] == "elasticsearch"


def test_health_reports_degraded_when_circuit_open(client):
    from resilience import get_breaker
    breaker = get_breaker("elasticsearch")
    breaker.state = "open"
    breaker.failures = 5

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert "circuit_open" in data["checks"]["elasticsearch_circuit"]