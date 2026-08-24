def test_create_and_list_organization(client):
    payload = {"name": "Acme Corp", "description": "Test tenant"}
    create_response = client.post("/organizations", json=payload)
    assert create_response.status_code == 200
    created = create_response.json()
    assert "id" in created

    list_response = client.get("/organizations")
    assert list_response.status_code == 200
    orgs = list_response.json()
    assert any(o["name"] == "Acme Corp" for o in orgs)


def test_create_organization_without_description(client):
    response = client.post("/organizations", json={"name": "NoDescCorp"})
    assert response.status_code == 200

    list_response = client.get("/organizations")
    match = next(o for o in list_response.json() if o["name"] == "NoDescCorp")
    assert match["description"] is None


def test_delete_organization(client):
    create_response = client.post("/organizations", json={"name": "TempOrg"})
    org_id = create_response.json()["id"]

    delete_response = client.delete(f"/organizations/{org_id}")
    assert delete_response.status_code == 200
    assert delete_response.json()["message"] == "Organization deleted"

    list_response = client.get("/organizations")
    assert not any(o["id"] == org_id for o in list_response.json())


def test_delete_nonexistent_organization(client):
    response = client.delete("/organizations/999999")
    assert response.status_code == 200
    assert response.json()["error"] == "Organization not found"