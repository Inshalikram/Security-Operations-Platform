def test_create_and_list_asset(client):
    payload = {
        "name": "test-server-01",
        "ip_address": "10.0.0.50",
        "asset_type": "server",
        "owner": "SOC Team",
        "criticality": "high"
    }
    create_response = client.post("/assets", json=payload)
    assert create_response.status_code == 200
    created = create_response.json()
    assert "id" in created

    list_response = client.get("/assets")
    assert list_response.status_code == 200
    assets = list_response.json()
    assert any(a["name"] == "test-server-01" for a in assets)


def test_create_asset_defaults(client):
    payload = {"name": "minimal-asset"}
    response = client.post("/assets", json=payload)
    assert response.status_code == 200

    list_response = client.get("/assets")
    match = next(a for a in list_response.json() if a["name"] == "minimal-asset")
    assert match["asset_type"] == "server"
    assert match["criticality"] == "medium"
    assert match["status"] == "active"


def test_delete_asset(client):
    create_response = client.post("/assets", json={"name": "to-be-deleted"})
    asset_id = create_response.json()["id"]

    delete_response = client.delete(f"/assets/{asset_id}")
    assert delete_response.status_code == 200
    assert delete_response.json()["message"] == "Asset deleted"

    list_response = client.get("/assets")
    assert not any(a["id"] == asset_id for a in list_response.json())


def test_delete_nonexistent_asset(client):
    response = client.delete("/assets/999999")
    assert response.status_code == 200
    assert response.json()["error"] == "Asset not found"