def test_sigma_evaluate_brute_force_match(client):
    payload = {"log_event": {"event_type": "failed_login", "src_ip": "10.0.0.5"}}
    response = client.post("/sigma/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    titles = [r["rule_title"] for r in data["matched_rules"]]
    assert "Multiple Failed Login Attempts (Brute Force)" in titles

def test_sigma_evaluate_no_match(client):
    payload = {"log_event": {"event_type": "successful_login", "src_ip": "10.0.0.5"}}
    response = client.post("/sigma/evaluate", json=payload)
    assert response.status_code == 200
    assert response.json()["matched_rules"] == []

def test_sigma_list_rules(client):
    response = client.get("/sigma/rules")
    assert response.status_code == 200
    assert len(response.json()) >= 2