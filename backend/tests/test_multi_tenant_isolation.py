"""
Multi-Tenant Isolation Test Suite.

Verifies:
1. Tenant A's token cannot read Tenant B's data via list endpoints (data is scoped, never leaked).
2. Tenant A's token cannot read Tenant B's data via direct GET /{id} (returns 403 Forbidden, not silently filtered).
3. Tenant A's token cannot write or delete Tenant B's data (returns 403 Forbidden).
4. Non-existent resources return 404 Not Found.
5. Client-side tenant_id spoofing in request payloads is overridden by the server session.
6. Covers all 8 tenant-scoped resource types + agent governance:
   - Incidents
   - Alerts (unified and direct)
   - Assets
   - Threat Intel Indicators
   - Reports
   - Playbooks / Knowledge Rules
   - API Credentials
   - AI Conversations
   - Agent Approvals and Audit Logs
"""

import pytest
from main import app
from auth import verify_token
from tenancy import get_current_tenant


def set_tenant_user(tenant_id: str, username: str = "analyst_user"):
    """Configures FastAPI dependency override to simulate a JWT token for the given tenant."""
    def _override():
        return {
            "preferred_username": username,
            "sub": f"user-sub-{tenant_id}",
            "tenant_id": tenant_id,
            "realm_access": {"roles": ["analyst"]},
        }
    app.dependency_overrides[verify_token] = _override


# ══════════════════════════════════════════════════════════════════════════
# 1. ASSETS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_asset_multi_tenant_isolation(client):
    # Tenant Alpha creates an asset
    set_tenant_user("tenant-alpha")
    res_create = client.post("/assets", json={"name": "Alpha-DC-01", "ip_address": "10.10.1.5"})
    assert res_create.status_code == 200
    asset_id = res_create.json()["id"]

    # Tenant Alpha can list and retrieve it
    res_list_a = client.get("/assets")
    assert any(a["id"] == asset_id for a in res_list_a.json())
    res_get_a = client.get(f"/assets/{asset_id}")
    assert res_get_a.status_code == 200
    assert res_get_a.json()["name"] == "Alpha-DC-01"

    # Tenant Beta cannot list it
    set_tenant_user("tenant-beta")
    res_list_b = client.get("/assets")
    assert not any(a["id"] == asset_id for a in res_list_b.json())

    # Tenant Beta direct GET -> 403 Forbidden
    res_get_b = client.get(f"/assets/{asset_id}")
    assert res_get_b.status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    res_del_b = client.delete(f"/assets/{asset_id}")
    assert res_del_b.status_code == 403

    # Non-existent ID -> 404 Not Found
    res_get_none = client.get("/assets/999999")
    assert res_get_none.status_code == 404

    # Cleanup: Tenant Alpha deletes own asset
    set_tenant_user("tenant-alpha")
    res_del_a = client.delete(f"/assets/{asset_id}")
    assert res_del_a.status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 2. INCIDENTS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_incident_multi_tenant_isolation(client):
    # Tenant Alpha creates an incident
    set_tenant_user("tenant-alpha")
    res_create = client.post("/incidents", json={
        "title": "Alpha Ransomware Detection",
        "severity": "critical",
        "description": "Host locked by ransomware"
    })
    assert res_create.status_code == 200
    inc_id = res_create.json()["id"]

    # Tenant Alpha can read
    res_get_a = client.get(f"/incidents/{inc_id}")
    assert res_get_a.status_code == 200
    assert res_get_a.json()["title"] == "Alpha Ransomware Detection"

    # Tenant Beta cannot list it
    set_tenant_user("tenant-beta")
    res_list_b = client.get("/incidents")
    assert not any(i["id"] == inc_id for i in res_list_b.json())

    # Tenant Beta GET -> 403 Forbidden
    res_get_b = client.get(f"/incidents/{inc_id}")
    assert res_get_b.status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    res_del_b = client.delete(f"/incidents/{inc_id}")
    assert res_del_b.status_code == 403

    # Non-existent incident -> 404
    assert client.get("/incidents/999999").status_code == 404

    # Cleanup by Tenant Alpha
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/incidents/{inc_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 3. THREAT INTEL INDICATORS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_indicator_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/threat-intel/indicators", json={
        "ip_address": "198.51.100.42",
        "verdict": "malicious",
        "malicious_signals": 3,
        "country": "DE"
    })
    assert res_create.status_code == 200
    ind_id = res_create.json()["id"]

    # Tenant Alpha sees it in history
    hist_a = client.get("/threat-intel/history").json()
    assert any(h["id"] == ind_id for h in hist_a)

    # Tenant Beta cannot see in history
    set_tenant_user("tenant-beta")
    hist_b = client.get("/threat-intel/history").json()
    assert not any(h["id"] == ind_id for h in hist_b)

    # Tenant Beta GET -> 403 Forbidden
    assert client.get(f"/threat-intel/indicators/{ind_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/threat-intel/indicators/{ind_id}").status_code == 403

    # Nonexistent indicator -> 404
    assert client.get("/threat-intel/indicators/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/threat-intel/indicators/{ind_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 4. ALERTS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_alerts_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/alerts", json={
        "alert_type": "suricata",
        "title": "ET EXPLOIT Possible CVE-2024-Exploit",
        "severity": "critical",
        "source_ip": "10.0.0.99",
        "dest_ip": "10.0.0.1"
    })
    assert res_create.status_code == 200
    alert_id = res_create.json()["id"]

    # Tenant Alpha sees it in unified alerts
    alerts_a = client.get("/alerts/unified").json()["alerts"]
    assert any(a.get("id") == alert_id and a.get("source") == "suricata" for a in alerts_a)

    # Tenant Beta does NOT see it in unified alerts
    set_tenant_user("tenant-beta")
    alerts_b = client.get("/alerts/unified").json()["alerts"]
    assert not any(a.get("id") == alert_id and a.get("source") == "suricata" for a in alerts_b)

    # Tenant Beta direct GET -> 403 Forbidden
    assert client.get(f"/alerts/{alert_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/alerts/{alert_id}").status_code == 403

    # Nonexistent alert -> 404
    assert client.get("/alerts/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/alerts/{alert_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 5. REPORTS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_reports_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/reports", json={
        "title": "Alpha Q3 SOC Executive Summary",
        "period": "monthly",
        "content": "Confidential Alpha Security Posture",
        "filename": "alpha_q3.txt"
    })
    assert res_create.status_code == 200
    report_id = res_create.json()["id"]

    # Tenant Alpha sees report
    assert client.get(f"/reports/{report_id}").status_code == 200

    # Tenant Beta does not see in list
    set_tenant_user("tenant-beta")
    reports_b = client.get("/reports").json()
    assert not any(r["id"] == report_id for r in reports_b)

    # Tenant Beta GET -> 403 Forbidden
    assert client.get(f"/reports/{report_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/reports/{report_id}").status_code == 403

    # Nonexistent -> 404
    assert client.get("/reports/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/reports/{report_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 6. PLAYBOOKS / KNOWLEDGE BASE ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_playbooks_knowledge_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/knowledge/chunks", json={
        "source_type": "playbook",
        "title": "Alpha Proprietary Containment Playbook",
        "content": "Step 1: Isolate Alpha core switches. Step 2: Revoke tokens."
    })
    assert res_create.status_code == 200
    chunk_id = res_create.json()["id"]

    # Tenant Alpha can access via chunks and playbooks endpoints
    assert client.get(f"/knowledge/chunks/{chunk_id}").status_code == 200
    assert client.get(f"/playbooks/{chunk_id}").status_code == 200

    # Tenant Beta cannot list it
    set_tenant_user("tenant-beta")
    playbooks_b = client.get("/playbooks").json()
    assert not any(p["id"] == chunk_id for p in playbooks_b)

    # Tenant Beta GET -> 403 Forbidden
    assert client.get(f"/knowledge/chunks/{chunk_id}").status_code == 403
    assert client.get(f"/playbooks/{chunk_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/knowledge/chunks/{chunk_id}").status_code == 403

    # Nonexistent -> 404
    assert client.get("/playbooks/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/knowledge/chunks/{chunk_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 7. API CREDENTIALS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_api_credentials_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/credentials", json={
        "name": "Alpha Production VT Key",
        "service": "virustotal",
        "key_value": "super-secret-alpha-api-key-9999"
    })
    assert res_create.status_code == 200
    cred_id = res_create.json()["id"]

    # Tenant Alpha lists and gets masked key
    creds_a = client.get("/credentials").json()
    match_a = next(c for c in creds_a if c["id"] == cred_id)
    assert match_a["masked_key"].startswith("supe...")
    assert "secret" not in match_a["masked_key"]

    # Tenant Beta cannot list it
    set_tenant_user("tenant-beta")
    creds_b = client.get("/credentials").json()
    assert not any(c["id"] == cred_id for c in creds_b)

    # Tenant Beta GET -> 403 Forbidden
    assert client.get(f"/credentials/{cred_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/credentials/{cred_id}").status_code == 403

    # Nonexistent -> 404
    assert client.get("/credentials/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/credentials/{cred_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 8. AI CONVERSATIONS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_ai_conversations_multi_tenant_isolation(client):
    set_tenant_user("tenant-alpha")
    res_create = client.post("/ai/conversations", json={
        "prompt": "Analyze secret exploit payload for Alpha infrastructure",
        "response": "Identified CVE-2024-zero-day on Alpha intranet",
        "feature": "cve_explain",
        "user_id": "alpha_analyst"
    })
    assert res_create.status_code == 200
    conv_id = res_create.json()["id"]

    # Tenant Alpha can access
    assert client.get(f"/ai/conversations/{conv_id}").status_code == 200

    # Tenant Beta does not see in list
    set_tenant_user("tenant-beta")
    convs_b = client.get("/ai/conversations").json()
    assert not any(c["id"] == conv_id for c in convs_b)

    # Tenant Beta GET -> 403 Forbidden
    assert client.get(f"/ai/conversations/{conv_id}").status_code == 403

    # Tenant Beta DELETE -> 403 Forbidden
    assert client.delete(f"/ai/conversations/{conv_id}").status_code == 403

    # Nonexistent -> 404
    assert client.get("/ai/conversations/999999").status_code == 404

    # Cleanup
    set_tenant_user("tenant-alpha")
    assert client.delete(f"/ai/conversations/{conv_id}").status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 9. AGENT GOVERNANCE & APPROVALS ISOLATION
# ══════════════════════════════════════════════════════════════════════════

def test_agent_approvals_multi_tenant_isolation(client):
    from main import SessionLocal, PendingApproval

    # Seed a pending action belonging to Tenant Alpha
    db = SessionLocal()
    pending = PendingApproval(
        tenant_id="tenant-alpha",
        agent_name="triage_agent",
        action_name="isolate_host",
        target="10.0.5.10",
        params={"host": "10.0.5.10"},
        risk_score=0.90,
        status="pending",
        reasoning="Suspicious lateral movement detected on Alpha network"
    )
    db.add(pending)
    db.commit()
    db.refresh(pending)
    action_id = pending.id
    db.close()

    # Tenant Alpha sees pending approval
    set_tenant_user("tenant-alpha")
    pending_a = client.get("/agents/pending-approvals").json()
    assert any(p["id"] == action_id for p in pending_a)

    # Tenant Beta does NOT see pending approval
    set_tenant_user("tenant-beta")
    pending_b = client.get("/agents/pending-approvals").json()
    assert not any(p["id"] == action_id for p in pending_b)

    # Tenant Beta attempting to APPROVE -> 403 Forbidden
    res_approve_b = client.post(f"/agents/approve/{action_id}")
    assert res_approve_b.status_code == 403

    # Tenant Beta attempting to REJECT -> 403 Forbidden
    res_reject_b = client.post(f"/agents/reject/{action_id}")
    assert res_reject_b.status_code == 403

    # Nonexistent action approval -> 404 Not Found
    assert client.post("/agents/approve/999999").status_code == 404

    # Tenant Alpha approves successfully
    set_tenant_user("tenant-alpha")
    res_approve_a = client.post(f"/agents/approve/{action_id}")
    assert res_approve_a.status_code == 200
    assert res_approve_a.json()["status"] == "executed"

    # Verify audit log isolation:
    # Tenant Alpha sees the approval in audit log
    audit_a = client.get("/agents/audit-log").json()
    assert any(entry["action_name"] == "isolate_host" for entry in audit_a)

    # Tenant Beta does NOT see Tenant Alpha's audit log entry
    set_tenant_user("tenant-beta")
    audit_b = client.get("/agents/audit-log").json()
    assert not any(entry.get("target") == "10.0.5.10" for entry in audit_b)


# ══════════════════════════════════════════════════════════════════════════
# 10. CLIENT-SIDE SPOOFING PREVENTION
# ══════════════════════════════════════════════════════════════════════════

def test_tenant_spoofing_prevented_by_session_layer(client):
    """If a client sends tenant_id='tenant-beta' in body, server forces caller's authenticated tenant."""
    set_tenant_user("tenant-alpha")
    res = client.post("/assets", json={
        "name": "Injected Server",
        "tenant_id": "tenant-beta"  # Malicious spoofing attempt
    })
    assert res.status_code == 200
    asset_id = res.json()["id"]

    # Verify asset was saved under tenant-alpha, not tenant-beta
    set_tenant_user("tenant-alpha")
    get_a = client.get(f"/assets/{asset_id}")
    assert get_a.status_code == 200
    assert get_a.json()["tenant_id"] == "tenant-alpha"

    # Tenant Beta cannot access it
    set_tenant_user("tenant-beta")
    get_b = client.get(f"/assets/{asset_id}")
    assert get_b.status_code == 403


# ══════════════════════════════════════════════════════════════════════════
# 11. CLAIM EXTRACTION FALLBACK HIERARCHY
# ══════════════════════════════════════════════════════════════════════════

def test_claim_extraction_hierarchy():
    # 1. Direct tenant_id
    assert get_current_tenant({"tenant_id": "t1", "organization_id": "t2"}) == "t1"

    # 2. organization_id
    assert get_current_tenant({"organization_id": "t2"}) == "t2"

    # 3. org_id
    assert get_current_tenant({"org_id": "t3"}) == "t3"

    # 4. Keycloak attributes list
    assert get_current_tenant({"attributes": {"tenant_id": ["t4"]}}) == "t4"

    # 5. Keycloak attributes string
    assert get_current_tenant({"attributes": {"tenant_id": "t5"}}) == "t5"

    # 6. Default fallback
    assert get_current_tenant({}) == "default"
