"""Registry of real actions agents can request, plus the request → approval →
execution → audit lifecycle. No destructive action ever executes without a
human calling approve_action()."""

from datetime import datetime
from policy_engine import check_policy, requires_human_approval, PolicyViolation


def execute_block_ip(target: str, params: dict) -> dict:
    """Demo action — in production this would call the firewall/Traefik API.
    Here it just records the block so the flow can be demonstrated end-to-end."""
    # TODO: wire to real firewall API when this becomes a production MSSP feature
    return {"blocked_ip": target, "method": "simulated", "note": "Firewall integration not yet wired"}


ACTION_REGISTRY = {
    "block_ip": execute_block_ip,
}


def request_action(db, agent_name: str, action_name: str, target: str,
                    params: dict = None, confidence: float = 1.0, reasoning: str = ""):
    """Called BY an agent when it wants to perform an action. Never executes
    a destructive action directly — always logs, and queues for approval
    if the action is destructive."""
    from main import AgentAction  # avoid circular import at module load time

    try:
        check_policy(agent_name, action_name, confidence)
    except PolicyViolation as e:
        record = AgentAction(
            agent_name=agent_name, action_name=action_name, target=target,
            params=params, confidence=str(confidence), status="denied",
            reasoning=str(e), requested_at=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        return {"status": "denied", "reason": str(e)}

    if requires_human_approval(action_name):
        record = AgentAction(
            agent_name=agent_name, action_name=action_name, target=target,
            params=params, confidence=str(confidence), status="pending",
            reasoning=reasoning, requested_at=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return {"status": "pending_approval", "action_id": record.id}

    # Non-destructive, policy-allowed action — safe to auto-execute
    executor = ACTION_REGISTRY.get(action_name)
    result = executor(target, params or {}) if executor else {"note": "no executor registered"}
    record = AgentAction(
        agent_name=agent_name, action_name=action_name, target=target,
        params=params, confidence=str(confidence), status="executed",
        reasoning=reasoning, requested_at=datetime.utcnow(),
        executed_at=datetime.utcnow(), result=result
    )
    db.add(record)
    db.commit()
    return {"status": "executed", "result": result}


def approve_action(db, action_id: int, approver: str):
    from main import AgentAction
    record = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not record:
        return {"error": "Action not found"}
    if record.status != "pending":
        return {"error": f"Action is '{record.status}', not pending"}

    executor = ACTION_REGISTRY.get(record.action_name)
    result = executor(record.target, record.params or {}) if executor else {"note": "no executor registered"}

    record.status = "executed"
    record.decided_by = approver
    record.decided_at = datetime.utcnow()
    record.executed_at = datetime.utcnow()
    record.result = result
    db.commit()
    return {"status": "executed", "result": result}


def reject_action(db, action_id: int, approver: str, reason: str = ""):
    from main import AgentAction
    record = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not record:
        return {"error": "Action not found"}
    if record.status != "pending":
        return {"error": f"Action is '{record.status}', not pending"}

    record.status = "rejected"
    record.decided_by = approver
    record.decided_at = datetime.utcnow()
    record.reasoning = (record.reasoning or "") + f" | Rejected: {reason}"
    db.commit()
    return {"status": "rejected"}