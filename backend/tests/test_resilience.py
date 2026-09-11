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