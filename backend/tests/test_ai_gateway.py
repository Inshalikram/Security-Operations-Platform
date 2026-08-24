import pytest
import main


def test_cve_explain_uses_ai_gateway(client, monkeypatch):
    def fake_call_ai(prompt, provider=None, feature="generic"):
        assert "CVE-2024-1234" in prompt
        assert feature == "cve_explain"
        return "This is a mocked CVE explanation."

    monkeypatch.setattr(main, "call_ai", fake_call_ai)

    response = client.get("/ai/cve/CVE-2024-1234")
    assert response.status_code == 200
    data = response.json()
    assert data["cve"] == "CVE-2024-1234"
    assert data["explanation"] == "This is a mocked CVE explanation."


def test_cve_explain_handles_ai_failure_gracefully(client, monkeypatch):
    def failing_call_ai(prompt, provider=None, feature="generic"):
        raise ConnectionError("AI provider unreachable")

    monkeypatch.setattr(main, "call_ai", failing_call_ai)

    response = client.get("/ai/cve/CVE-2024-1234")
    assert response.status_code == 200
    assert "error" in response.json()


def test_malware_explain_with_hash_only(client, monkeypatch):
    def fake_call_ai(prompt, provider=None, feature="generic"):
        assert feature == "malware_explain"
        return "Looks like a mocked dropper."

    monkeypatch.setattr(main, "call_ai", fake_call_ai)

    payload = {"hash": "d41d8cd98f00b204e9800998ecf8427e"}
    response = client.post("/ai/malware-explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["ai_explanation"] == "Looks like a mocked dropper."
    assert data["input"]["hash"] == payload["hash"]


def test_call_ai_rejects_unknown_provider():
    with pytest.raises(ValueError):
        main.call_ai("test prompt", provider="not-a-real-provider")