"""Policy Engine — every agent action that touches the real world (block IP,
isolate host, etc.) must go through here. Read-only actions execute directly;
destructive actions are queued for human approval and never auto-execute."""

from datetime import datetime

DESTRUCTIVE_ACTIONS = {
    "block_ip", "isolate_host", "delete_evidence",
    "modify_firewall_rule", "disable_account",
}

# Per-agent policy — deny-by-default: anything not explicitly allowed is denied.
AGENT_POLICIES = {
    "threat_hunt_agent": {
        "allowed_operations": {"read_threat_intel", "generate_report"},
        "confidence_threshold": 0.0,
        "timeout_seconds": 60,
        "retry_limit": 2,
        "max_tool_calls": 5,
    },
    "triage_agent": {
        "allowed_operations": {"read_threat_intel", "classify_severity", "block_ip"},
        "confidence_threshold": 0.75,   # only proposes block_ip above this confidence
        "timeout_seconds": 60,
        "retry_limit": 2,
        "max_tool_calls": 5,
    },
    "malware_agent": {
        "allowed_operations": {"query_virustotal", "generate_report"},
        "confidence_threshold": 0.0,
        "timeout_seconds": 60,
        "retry_limit": 2,
        "max_tool_calls": 5,
    },
    "exec_report_agent": {
        "allowed_operations": {"read_db", "generate_report"},
        "confidence_threshold": 0.0,
        "timeout_seconds": 120,
        "retry_limit": 1,
        "max_tool_calls": 3,
    },
}


class PolicyViolation(Exception):
    pass


def check_policy(agent_name: str, action_name: str, confidence: float = 1.0):
    """Raises PolicyViolation if the agent isn't allowed to even propose this action."""
    policy = AGENT_POLICIES.get(agent_name)
    if not policy:
        raise PolicyViolation(f"No policy defined for agent '{agent_name}' — denied by default")
    if action_name not in policy["allowed_operations"]:
        raise PolicyViolation(f"Agent '{agent_name}' is not permitted to perform '{action_name}'")
    if confidence < policy["confidence_threshold"]:
        raise PolicyViolation(
            f"Confidence {confidence:.2f} below required threshold {policy['confidence_threshold']} for '{action_name}'"
        )
    return policy


def requires_human_approval(action_name: str) -> bool:
    return action_name in DESTRUCTIVE_ACTIONS