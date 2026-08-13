def test_yara_scan_detects_encoded_powershell(client):
    payload = {"content": "powershell -EncodedCommand aGVsbG8gd29ybGQ="}
    response = client.post("/yara/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["matches_found"] >= 1
    rule_names = [m["rule"] for m in data["matches"]]
    assert "Suspicious_PowerShell_Encoded_Command" in rule_names

def test_yara_scan_clean_content(client):
    payload = {"content": "this is just a normal harmless sentence"}
    response = client.post("/yara/scan", json=payload)
    assert response.status_code == 200
    assert response.json()["matches_found"] == 0