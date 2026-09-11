"""Registry of real actions agents can request, plus the request → approval →
execution → audit lifecycle. No destructive action ever executes without a
human calling approve_action()."""

from datetime import datetime
from typing import Dict, Any, Optional
from policy_engine import (
    policy_middleware,
    DESTRUCTIVE_OPERATIONS,
    calculate_risk_score,
    requires_human_approval,
)


def execute_block_ip(target: str, params: dict) -> dict:
    """Blocks an IP address at the firewall/gateway."""
    return {"blocked_ip": target, "method": "simulated_firewall", "status": "blocked"}


def execute_isolate_host(target: str, params: dict) -> dict:
    """Isolates an endpoint from the enterprise network."""
    return {"isolated_host": target, "method": "simulated_edr", "status": "isolated"}


def execute_delete_evidence(target: str, params: dict) -> dict:
    """Deletes evidence files or artifacts."""
    return {"deleted_target": target, "method": "simulated_storage", "status": "deleted"}


def execute_modify_firewall(target: str, params: dict) -> dict:
    """Modifies ingress/egress firewall rules."""
    return {"firewall_target": target, "rule": params.get("rule", "drop"), "status": "rule_applied"}


def execute_disable_account(target: str, params: dict) -> dict:
    """Disables a compromised user account in directory service."""
    return {"disabled_account": target, "method": "simulated_iam", "status": "disabled"}


ACTION_REGISTRY = {
    "block_ip": execute_block_ip,
    "isolate_host": execute_isolate_host,
    "delete_evidence": execute_delete_evidence,
    "modify_firewall": execute_modify_firewall,
    "modify_firewall_rule": execute_modify_firewall,
    "disable_account": execute_disable_account,
}

# Register handlers with policy_middleware
for act, fn in ACTION_REGISTRY.items():
    policy_middleware.register_action(act, fn)


def request_action(
    db,
    agent_name: str,
    action_name: str,
    target: str,
    params: Optional[dict] = None,
    confidence: float = 1.0,
    reasoning: str = "",
    call_count: int = 1,
) -> dict:
    """Called by an agent when proposing or executing a tool action.
    Passes through PolicyEngineMiddleware:
    Agent → Policy Check → Risk Score → (if destructive) Human Approval Queue → Action → Audit Log
    """
    return policy_middleware.process_tool_call(
        db=db,
        agent_name=agent_name,
        tool_name=action_name,
        tool_input=params or {},
        confidence=confidence,
        reasoning=reasoning,
        target=target,
        call_count=call_count,
    )


def approve_action(db, action_id: int, approver: str) -> dict:
    """Approves and executes a previously queued destructive action."""
    from main import PendingApproval, AgentAction, AgentAuditLog

    # Check PendingApproval first
    record = db.query(PendingApproval).filter(PendingApproval.id == action_id).first()
    legacy_record = None
    if not record:
        legacy_record = db.query(AgentAction).filter(AgentAction.id == action_id).first()
        if not legacy_record:
            return {"error": "Action not found"}
        action_name = legacy_record.action_name
        target = legacy_record.target
        params = legacy_record.params or {}
        status = legacy_record.status
        reasoning = legacy_record.reasoning
        confidence = float(legacy_record.confidence) if legacy_record.confidence else 1.0
    else:
        action_name = record.action_name
        target = record.target
        params = record.params or {}
        status = record.status
        reasoning = record.reasoning
        confidence = record.confidence

    if status != "pending":
        return {"error": f"Action is '{status}', not pending"}

    # Execute the action via registered executor
    executor = ACTION_REGISTRY.get(action_name)
    result = executor(target, params) if executor else {"note": f"No executor registered for {action_name}"}

    # Update record
    now = datetime.utcnow()
    if record:
        record.status = "executed"
        record.decided_by = approver
        record.decided_at = now
        record.executed_at = now
        record.result = result

    if legacy_record or record:
        leg = legacy_record or db.query(AgentAction).filter(AgentAction.id == action_id).first()
        if leg:
            leg.status = "executed"
            leg.decided_by = approver
            leg.decided_at = now
            leg.executed_at = now
            leg.result = result

    # Log approval to AgentAuditLog
    risk = calculate_risk_score(action_name, confidence, params)
    audit_entry = AgentAuditLog(
        agent_name=record.agent_name if record else legacy_record.agent_name,
        tool_name=action_name,
        tool_input=params,
        decision="approved",
        risk_score=risk,
        confidence=confidence,
        reasoning=f"Approved by {approver}. Prior reasoning: {reasoning}",
        approver=approver,
        result=result,
        created_at=now,
    )
    db.add(audit_entry)
    db.commit()

    return {"status": "executed", "result": result}


def reject_action(db, action_id: int, approver: str, reason: str = "") -> dict:
    """Rejects a previously queued destructive action."""
    from main import PendingApproval, AgentAction, AgentAuditLog

    record = db.query(PendingApproval).filter(PendingApproval.id == action_id).first()
    legacy_record = None
    if not record:
        legacy_record = db.query(AgentAction).filter(AgentAction.id == action_id).first()
        if not legacy_record:
            return {"error": "Action not found"}
        status = legacy_record.status
        action_name = legacy_record.action_name
        confidence = float(legacy_record.confidence) if legacy_record.confidence else 1.0
        params = legacy_record.params or {}
        agent_name = legacy_record.agent_name
    else:
        status = record.status
        action_name = record.action_name
        confidence = record.confidence
        params = record.params or {}
        agent_name = record.agent_name

    if status != "pending":
        return {"error": f"Action is '{status}', not pending"}

    now = datetime.utcnow()
    reject_reason = f"Rejected by {approver}: {reason}" if reason else f"Rejected by {approver}"

    if record:
        record.status = "rejected"
        record.decided_by = approver
        record.decided_at = now
        record.reasoning = (record.reasoning or "") + f" | {reject_reason}"

    leg = legacy_record or db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if leg:
        leg.status = "rejected"
        leg.decided_by = approver
        leg.decided_at = now
        leg.reasoning = (leg.reasoning or "") + f" | {reject_reason}"

    # Log rejection to AgentAuditLog
    risk = calculate_risk_score(action_name, confidence, params)
    audit_entry = AgentAuditLog(
        agent_name=agent_name,
        tool_name=action_name,
        tool_input=params,
        decision="rejected",
        risk_score=risk,
        confidence=confidence,
        reasoning=reject_reason,
        approver=approver,
        result={"status": "rejected", "reason": reason},
        created_at=now,
    )
    db.add(audit_entry)
    db.commit()

    return {"status": "rejected"}