import main


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def fake_requests_get_clean(url, headers=None, params=None, timeout=None):
    if "virustotal.com" in url:
        return FakeResponse({
            "data": {"attributes": {
                "reputation": 0, "country": "US",
                "total_votes": {"malicious": 0, "harmless": 20}
            }}
        })
    if "abuseipdb.com" in url:
        return FakeResponse({
            "data": {"abuseConfidenceScore": 0, "totalReports": 0,
                     "countryCode": "US", "isp": "Test ISP", "isWhitelisted": True}
        })
    if "alienvault.com" in url:
        return FakeResponse({
            "reputation": 0, "country_name": "United States",
            "pulse_info": {"count": 0}, "asn": "AS0000"
        })
    if "shodan.io" in url:
        return FakeResponse({
            "org": "Test Org", "country_name": "US",
            "ports": [443], "hostnames": [], "vulns": []
        })
    raise AssertionError(f"Unexpected URL requested: {url}")


def fake_requests_get_malicious(url, headers=None, params=None, timeout=None):
    if "virustotal.com" in url:
        return FakeResponse({
            "data": {"attributes": {
                "reputation": -50, "country": "RU",
                "total_votes": {"malicious": 15, "harmless": 1}
            }}
        })
    if "abuseipdb.com" in url:
        return FakeResponse({
            "data": {"abuseConfidenceScore": 85, "totalReports": 40,
                     "countryCode": "RU", "isp": "Bad ISP", "isWhitelisted": False}
        })
    if "alienvault.com" in url:
        return FakeResponse({
            "reputation": -10, "country_name": "Russia",
            "pulse_info": {"count": 5}, "asn": "AS1111"
        })
    if "shodan.io" in url:
        return FakeResponse({
            "org": "Bad Org", "country_name": "RU",
            "ports": [22, 3389], "hostnames": [], "vulns": ["CVE-2021-1111"]
        })
    raise AssertionError(f"Unexpected URL requested: {url}")


def test_unified_check_clean_verdict(client, monkeypatch):
    monkeypatch.setattr(main.requests, "get", fake_requests_get_clean)

    response = client.get("/threat-intel/check/8.8.8.8")
    assert response.status_code == 200
    data = response.json()
    assert data["overall_verdict"] == "clean"
    assert data["malicious_signals"] == 0
    assert set(data["sources_checked"]) == {"virustotal", "abuseipdb", "otx", "shodan"}
    assert "thehive_case" not in data


def test_unified_check_malicious_verdict(client, monkeypatch):
    monkeypatch.setattr(main.requests, "get", fake_requests_get_malicious)
    monkeypatch.setattr(
        main.requests, "post",
        lambda *a, **k: FakeResponse({"_id": "fake-case-id", "title": "mocked"})
    )

    response = client.get("/threat-intel/check/1.2.3.4")
    assert response.status_code == 200
    data = response.json()
    assert data["overall_verdict"] == "malicious"
    assert data["malicious_signals"] >= 2


def test_threat_intel_history_returns_list(client, monkeypatch):
    monkeypatch.setattr(main.requests, "get", fake_requests_get_clean)
    client.get("/threat-intel/check/8.8.4.4")  # ensure at least one record exists

    response = client.get("/threat-intel/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)