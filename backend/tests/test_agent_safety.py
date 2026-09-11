import pytest
from policy_engine import (
    TOOL_PERMISSIONS,
    DESTRUCTIVE_OPERATIONS,
    calculate_risk_score,
    check_policy,
    requires_human_approval,
    PolicyViolation,
    policy_middleware,
)
from governance import (
    request_action,
    approve_action,
    reject_action,
    ACTION_REGISTRY,
)
from main import SessionLocal, PendingApproval, AgentAuditLog, AgentAction
from agents import (
    threat_hunting_agent,
    triage_agent,
    malware_agent,
    exec_reporting_agent,
)


def test_tool_permissions_structure_per_agent():
    """Verify each agent has explicit allowed_operations, denied_operations,
    confidence_threshold, timeout, max_tool_calls, and retry_limit."""
    required_keys = {
        "allowed_operations",
        "denied_operations",
        "confidence_threshold",
        "timeout",
        "max_tool_calls",
        "retry_limit",
    }
    for agent_name, perms in TOOL_PERMISSIONS.items():
        assert required_keys.issubset(perms.keys()), f"Missing keys in {agent_name}"
        assert isinstance(perms["allowed_operations"], set)
        assert isinstance(perms["denied_operations"], set)
        assert isinstance(perms["confidence_threshold"], (int, float))
        assert isinstance(perms["timeout"], int)
        assert isinstance(perms["max_tool_calls"], int)
        assert isinstance(perms["retry_limit"], int)

    # Verify compiled agents have tool_permissions attached
    assert hasattr(threat_hunting_agent, "tool_permissions")
    assert hasattr(triage_agent, "tool_permissions")
    assert hasattr(malware_agent, "tool_permissions")
    assert hasattr(exec_reporting_agent, "tool_permissions")


def test_explicit_denied_operation_is_blocked():
    """Agents cannot perform explicitly denied operations."""
    # threat_hunt_agent is denied block_ip
    with pytest.raises(PolicyViolation) as excinfo:
        check_policy("threat_hunt_agent", "block_ip")
    assert "explicitly denied" in str(excinfo.value)

    # malware_agent is denied isolate_host
    with pytest.raises(PolicyViolation) as excinfo:
        check_policy("malware_agent", "isolate_host")
    assert "explicitly denied" in str(excinfo.value)


def test_unregistered_operation_is_blocked():
    """Operations not explicitly allowed are denied by default."""
    with pytest.raises(PolicyViolation) as excinfo:
        check_policy("threat_hunt_agent", "format_hard_drive")
    assert "not in allowed operations" in str(excinfo.value)


def test_confidence_threshold_enforcement():
    """Operations requiring high confidence are rejected when below threshold."""
    # triage_agent requires 0.75 confidence for block_ip
    with pytest.raises(PolicyViolation) as excinfo:
        check_policy("triage_agent", "block_ip", confidence=0.5)
    assert "below required threshold" in str(excinfo.value)

    # With confidence 0.80, it passes policy check
    policy = check_policy("triage_agent", "block_ip", confidence=0.80)
    assert policy is not None


def test_max_tool_calls_budget_enforcement():
    """Agents exceeding max_tool_calls budget are blocked."""
    # exec_report_agent has max_tool_calls=3
    with pytest.raises(PolicyViolation) as excinfo:
        check_policy("exec_report_agent", "generate_report", call_count=4)
    assert "exceeded max tool call limit" in str(excinfo.value)


def test_destructive_operations_definitions():
    """All 5 critical destructive operations must be defined."""
    expected_destructive = {
        "block_ip",
        "isolate_host",
        "delete_evidence",
        "modify_firewall",
        "disable_account",
    }
    assert expected_destructive.issubset(DESTRUCTIVE_OPERATIONS)
    for op in expected_destructive:
        assert requires_human_approval(op) is True
        assert calculate_risk_score(op) >= 0.80


def test_middleware_intercepts_destructive_operation_to_pending_approvals():
    """Destructive operations must NEVER execute directly; they write to pending_approvals."""
    db = SessionLocal()
    try:
        res = request_action(
            db,
            agent_name="triage_agent",
            action_name="block_ip",
            target="198.51.100.23",
            params={"ip_address": "198.51.100.23"},
            confidence=0.95,
            reasoning="Active C2 beaconing detected",
        )
        assert res["status"] == "pending_approval"
        assert "approval_id" in res
        approval_id = res["approval_id"]

        # Verify entry in pending_approvals table
        approval = db.query(PendingApproval).filter(PendingApproval.id == approval_id).first()
        assert approval is not None
        assert approval.status == "pending"
        assert approval.action_name == "block_ip"
        assert approval.target == "198.51.100.23"
        assert approval.risk_score >= 0.80

        # Verify audit log recorded queued_for_approval
        audit = db.query(AgentAuditLog).filter(
            AgentAuditLog.tool_name == "block_ip",
            AgentAuditLog.decision == "queued_for_approval"
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_human_approval_workflow():
    """Human approval executes the queued destructive action and records audit log."""
    db = SessionLocal()
    try:
        # Create a pending approval
        req = request_action(
            db,
            agent_name="triage_agent",
            action_name="block_ip",
            target="203.0.113.50",
            params={"ip_address": "203.0.113.50"},
            confidence=0.90,
            reasoning="DDoS source",
        )
        action_id = req["approval_id"]

        # Approve action
        result = approve_action(db, action_id, approver="soc_lead")
        assert result["status"] == "executed"
        assert "result" in result

        # Verify record updated
        approval = db.query(PendingApproval).filter(PendingApproval.id == action_id).first()
        assert approval.status == "executed"
        assert approval.decided_by == "soc_lead"
        assert approval.executed_at is not None

        # Verify audit log
        audit = db.query(AgentAuditLog).filter(
            AgentAuditLog.tool_name == "block_ip",
            AgentAuditLog.decision == "approved",
            AgentAuditLog.approver == "soc_lead"
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_human_rejection_workflow():
    """Human rejection rejects the action, does not execute, and logs to audit trail."""
    db = SessionLocal()
    try:
        req = request_action(
            db,
            agent_name="triage_agent",
            action_name="block_ip",
            target="192.0.2.1",
            params={"ip_address": "192.0.2.1"},
            confidence=0.85,
            reasoning="Test false positive",
        )
        action_id = req["approval_id"]

        # Reject action
        result = reject_action(db, action_id, approver="soc_analyst", reason="Known CDN IP")
        assert result["status"] == "rejected"

        # Verify record updated
        approval = db.query(PendingApproval).filter(PendingApproval.id == action_id).first()
        assert approval.status == "rejected"
        assert approval.decided_by == "soc_analyst"

        # Verify audit log
        audit = db.query(AgentAuditLog).filter(
            AgentAuditLog.tool_name == "block_ip",
            AgentAuditLog.decision == "rejected",
            AgentAuditLog.approver == "soc_analyst"
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_non_destructive_tool_call_executes_directly():
    """Non-destructive operations (read/classify) execute directly and log to agent_audit_log."""
    db = SessionLocal()
    try:
        res = request_action(
            db,
            agent_name="threat_hunt_agent",
            action_name="read_threat_intel",
            target="8.8.8.8",
            params={"ip_address": "8.8.8.8"},
            confidence=1.0,
            reasoning="Automated telemetry check",
        )
        assert res["status"] == "executed"
        assert res["risk_score"] < 0.70

        # Verify audit log recorded execution
        audit = db.query(AgentAuditLog).filter(
            AgentAuditLog.agent_name == "threat_hunt_agent",
            AgentAuditLog.tool_name == "read_threat_intel",
            AgentAuditLog.decision == "executed"
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_pending_approvals_api_endpoints(client):
    """Test GET /agents/pending-approvals, POST /agents/approve, and GET /agents/audit-log via API."""
    db = SessionLocal()
    try:
        req = request_action(
            db,
            agent_name="triage_agent",
            action_name="block_ip",
            target="198.51.100.99",
            params={"ip_address": "198.51.100.99"},
            confidence=0.90,
            reasoning="API test incident",
        )
        action_id = req["approval_id"]
    finally:
        db.close()

    # 1. List pending approvals
    list_resp = client.get("/agents/pending-approvals")
    assert list_resp.status_code == 200
    pending_items = list_resp.json()
    assert any(item["id"] == action_id for item in pending_items)

    # 2. Approve action via API
    approve_resp = client.post(f"/agents/approve/{action_id}")
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "executed"

    # 3. Verify it is no longer in pending list
    list_resp_2 = client.get("/agents/pending-approvals")
    assert not any(item["id"] == action_id for item in list_resp_2.json())

    # 4. Check audit log via API
    audit_resp = client.get("/agents/audit-log")
    assert audit_resp.status_code == 200
    audit_logs = audit_resp.json()
    assert len(audit_logs) > 0
    assert any(log["decision"] in ("approved", "executed") for log in audit_logs)
