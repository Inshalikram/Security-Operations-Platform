"""Policy Engine — Agent Safety Controls & Governance Middleware
Enforces per-agent tool permissions, risk scoring, human approval queue
for destructive operations, and immutable audit logging.

Pipeline:
Agent → Policy Check → Risk Score → (if destructive) Human Approval Queue → Action → Audit Log
"""

from datetime import datetime
from typing import Dict, Any, Set, Optional

# ── Destructive Operations: never executed automatically by any agent ──
DESTRUCTIVE_OPERATIONS: Set[str] = {
    "block_ip",
    "isolate_host",
    "delete_evidence",
    "modify_firewall",
    "modify_firewall_rule",
    "disable_account",
}

# Alias for backward compatibility
DESTRUCTIVE_ACTIONS = DESTRUCTIVE_OPERATIONS


# ── Per-Agent Tool Permissions Config ──
# Explicit allowed_operations, denied_operations, confidence_threshold, timeout, max_tool_calls, retry_limit
TOOL_PERMISSIONS: Dict[str, Dict[str, Any]] = {
    "threat_hunt_agent": {
        "allowed_operations": {"read_threat_intel", "generate_report"},
        "denied_operations": {
            "block_ip", "isolate_host", "delete_evidence",
            "modify_firewall", "modify_firewall_rule", "disable_account"
        },
        "confidence_threshold": 0.0,
        "timeout": 60,
        "max_tool_calls": 5,
        "retry_limit": 2,
    },
    "triage_agent": {
        "allowed_operations": {
            "read_threat_intel", "classify_severity", "block_ip",
            "auto_assign", "generate_report"
        },
        "denied_operations": {
            "isolate_host", "delete_evidence", "modify_firewall",
            "modify_firewall_rule", "disable_account"
        },
        "confidence_threshold": 0.75,  # Only high confidence allows proposing block_ip
        "timeout": 60,
        "max_tool_calls": 5,
        "retry_limit": 2,
    },
    "malware_agent": {
        "allowed_operations": {
            "query_virustotal", "assess_risk", "recommend_containment",
            "generate_report"
        },
        "denied_operations": {
            "block_ip", "isolate_host", "delete_evidence",
            "modify_firewall", "modify_firewall_rule", "disable_account"
        },
        "confidence_threshold": 0.0,
        "timeout": 60,
        "max_tool_calls": 5,
        "retry_limit": 2,
    },
    "exec_report_agent": {
        "allowed_operations": {
            "read_db", "gather_recent_incidents", "compute_stats",
            "generate_report"
        },
        "denied_operations": {
            "block_ip", "isolate_host", "delete_evidence",
            "modify_firewall", "modify_firewall_rule", "disable_account"
        },
        "confidence_threshold": 0.0,
        "timeout": 120,
        "max_tool_calls": 3,
        "retry_limit": 1,
    },
}

# Alias for backward compatibility
AGENT_POLICIES = TOOL_PERMISSIONS


class PolicyViolation(Exception):
    """Raised when an agent action violates security boundaries or permissions."""
    pass


def calculate_risk_score(action_name: str, confidence: float = 1.0, params: Optional[dict] = None) -> float:
    """Calculates an action risk score from 0.0 (safe read-only) to 1.0 (extreme blast radius)."""
    base_scores = {
        "delete_evidence": 1.0,
        "disable_account": 0.95,
        "modify_firewall": 0.90,
        "modify_firewall_rule": 0.90,
        "isolate_host": 0.90,
        "block_ip": 0.85,
        "query_virustotal": 0.20,
        "read_threat_intel": 0.15,
        "read_db": 0.10,
        "classify_severity": 0.10,
        "generate_report": 0.10,
        "auto_assign": 0.10,
    }

    base = base_scores.get(action_name, 0.50)
    if action_name in DESTRUCTIVE_OPERATIONS:
        # Destructive actions are always >= 0.80 regardless of confidence
        return round(max(0.80, min(1.0, base)), 2)
    return round(base, 2)


def check_policy(agent_name: str, action_name: str, confidence: float = 1.0, call_count: int = 1) -> dict:
    """Policy Check step:
    Validates permissions, explicit deny lists, tool call budgets, and confidence thresholds.
    """
    policy = TOOL_PERMISSIONS.get(agent_name)
    if not policy:
        raise PolicyViolation(f"No security policy defined for agent '{agent_name}' — denied by default")

    # 1. Explicit Deny Check
    if action_name in policy.get("denied_operations", set()):
        raise PolicyViolation(f"Operation '{action_name}' is explicitly denied for agent '{agent_name}'")

    # 2. Allowed Check
    if action_name not in policy.get("allowed_operations", set()):
        raise PolicyViolation(f"Operation '{action_name}' is not in allowed operations for agent '{agent_name}'")

    # 3. Tool Call Budget Check
    max_calls = policy.get("max_tool_calls", 5)
    if call_count > max_calls:
        raise PolicyViolation(f"Agent '{agent_name}' exceeded max tool call limit ({call_count} > {max_calls})")

    # 4. Confidence Threshold Check
    min_confidence = policy.get("confidence_threshold", 0.0)
    if confidence < min_confidence:
        raise PolicyViolation(
            f"Confidence {confidence:.2f} below required threshold {min_confidence:.2f} for '{action_name}'"
        )

    return policy


def requires_human_approval(action_name: str, risk_score: Optional[float] = None) -> bool:
    """Returns True if the operation is destructive or risk score is >= 0.70."""
    if action_name in DESTRUCTIVE_OPERATIONS:
        return True
    if risk_score is not None and risk_score >= 0.70:
        return True
    return False


class PolicyEngineMiddleware:
    """Middleware enforcing the full safety lifecycle for every agent tool invocation:
    Agent → Policy Check → Risk Score → (if destructive) Human Approval Queue → Action → Audit Log
    """

    def __init__(self, action_registry: Optional[dict] = None):
        self.action_registry = action_registry or {}

    def register_action(self, name: str, handler):
        self.action_registry[name] = handler

    def process_tool_call(
        self,
        db,
        agent_name: str,
        tool_name: str,
        tool_input: Optional[dict] = None,
        confidence: float = 1.0,
        reasoning: str = "",
        target: Optional[str] = None,
        call_count: int = 1,
    ) -> dict:
        """Executes the complete safety lifecycle pipeline."""
        from main import PendingApproval, AgentAuditLog, AgentAction

        tool_input = tool_input or {}
        target = target or tool_input.get("ip_address") or tool_input.get("target") or "system"

        # Step 1: Policy Check
        try:
            check_policy(agent_name, tool_name, confidence=confidence, call_count=call_count)
        except PolicyViolation as e:
            # Audit log the policy violation denial
            risk = calculate_risk_score(tool_name, confidence, tool_input)
            audit_entry = AgentAuditLog(
                agent_name=agent_name,
                tool_name=tool_name,
                tool_input=tool_input,
                decision="denied",
                risk_score=risk,
                confidence=confidence,
                reasoning=str(e),
                approver=None,
                result={"error": str(e)},
                created_at=datetime.utcnow()
            )
            db.add(audit_entry)
            db.commit()
            return {"status": "denied", "reason": str(e), "risk_score": risk}

        # Step 2: Risk Score calculation
        risk_score = calculate_risk_score(tool_name, confidence, tool_input)

        # Step 3: Human Approval Queue if destructive or high risk
        if requires_human_approval(tool_name, risk_score):
            pending_record = PendingApproval(
                agent_name=agent_name,
                action_name=tool_name,
                target=target,
                params=tool_input,
                risk_score=risk_score,
                confidence=confidence,
                status="pending",
                reasoning=reasoning,
                requested_at=datetime.utcnow(),
            )
            db.add(pending_record)
            db.commit()
            db.refresh(pending_record)

            # Also record in agent_actions for backward compatibility
            legacy_record = AgentAction(
                id=pending_record.id,
                agent_name=agent_name,
                action_name=tool_name,
                target=target,
                params=tool_input,
                confidence=str(confidence),
                status="pending",
                reasoning=reasoning,
                requested_at=datetime.utcnow(),
            )
            try:
                db.add(legacy_record)
                db.commit()
            except Exception:
                db.rollback()

            # Audit Log: Queued for Human Review
            audit_entry = AgentAuditLog(
                agent_name=agent_name,
                tool_name=tool_name,
                tool_input=tool_input,
                decision="queued_for_approval",
                risk_score=risk_score,
                confidence=confidence,
                reasoning=reasoning,
                approver=None,
                result={"pending_approval_id": pending_record.id},
                created_at=datetime.utcnow()
            )
            db.add(audit_entry)
            db.commit()

            return {
                "status": "pending_approval",
                "approval_id": pending_record.id,
                "action_id": pending_record.id,
                "risk_score": risk_score,
                "note": f"Destructive action '{tool_name}' safely queued for human review."
            }

        # Step 4: Action Execution (for non-destructive operations)
        executor = self.action_registry.get(tool_name)
        if executor:
            try:
                action_result = executor(target, tool_input)
            except Exception as e:
                action_result = {"error": f"Execution failed: {str(e)}"}
        else:
            action_result = {"status": "executed", "note": "Safe operation acknowledged"}

        # Step 5: Audit Log
        audit_entry = AgentAuditLog(
            agent_name=agent_name,
            tool_name=tool_name,
            tool_input=tool_input,
            decision="executed",
            risk_score=risk_score,
            confidence=confidence,
            reasoning=reasoning,
            approver="system_auto_approved",
            result=action_result,
            created_at=datetime.utcnow()
        )
        db.add(audit_entry)
        db.commit()

        return {
            "status": "executed",
            "result": action_result,
            "risk_score": risk_score
        }


# Global default middleware instance
policy_middleware = PolicyEngineMiddleware()