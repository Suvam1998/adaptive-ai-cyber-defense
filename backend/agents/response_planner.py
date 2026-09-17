"""Response Planning Agent.

Generates one or more candidate response plans for an incident. Every plan is
fully specified: action, target, reason, evidence, response risk, expected
outcome and a rollback method. Plans are informed by validated incident memory
where available.
"""
from __future__ import annotations

from .context import IncidentContext

# action templates keyed by attack type. response_risk: low/medium/high.
PLAYBOOK: dict[str, list[dict]] = {
    "brute_force": [
        {"action": "Block source IP", "target_field": "source_ip",
         "response_risk": "low", "rollback": "Remove IP from blocklist",
         "expected": "Failed login attempts from the IP stop."},
        {"action": "Enforce MFA / lock targeted account", "target_field": "user",
         "response_risk": "medium", "rollback": "Re-enable account after review",
         "expected": "Targeted account protected from further guessing."},
    ],
    "credential_compromise": [
        {"action": "Disable compromised account", "target_field": "user",
         "response_risk": "medium", "rollback": "Re-enable account & reset creds",
         "expected": "Attacker loses access via the account."},
        {"action": "Block source IP", "target_field": "source_ip",
         "response_risk": "low", "rollback": "Remove IP from blocklist",
         "expected": "Attacker source network blocked."},
        {"action": "Revoke active sessions", "target_field": "user",
         "response_risk": "medium", "rollback": "N/A (user re-authenticates)",
         "expected": "Active hijacked sessions terminated."},
    ],
    "port_scan": [
        {"action": "Block source IP", "target_field": "source_ip",
         "response_risk": "low", "rollback": "Remove IP from blocklist",
         "expected": "Scanning traffic from the source stops."},
    ],
    "suspicious_powershell": [
        {"action": "Isolate endpoint", "target_field": "host",
         "response_risk": "high", "rollback": "Restore network connectivity",
         "expected": "Host contained; no further script activity."},
        {"action": "Terminate suspicious process", "target_field": "process",
         "response_risk": "medium", "rollback": "N/A (process restart if benign)",
         "expected": "Malicious script stops executing."},
    ],
    "privilege_escalation": [
        {"action": "Disable account", "target_field": "user",
         "response_risk": "medium", "rollback": "Re-enable after review",
         "expected": "Escalation path via account closed."},
        {"action": "Isolate endpoint", "target_field": "host",
         "response_risk": "high", "rollback": "Restore network connectivity",
         "expected": "Host contained pending forensics."},
    ],
    "data_exfiltration": [
        {"action": "Block destination IP/domain", "target_field": "destination_ip",
         "response_risk": "low", "rollback": "Remove from blocklist",
         "expected": "Exfil channel severed."},
        {"action": "Isolate endpoint", "target_field": "host",
         "response_risk": "high", "rollback": "Restore network connectivity",
         "expected": "Source host contained; data flow stopped."},
    ],
    "lateral_movement": [
        {"action": "Disable account", "target_field": "user",
         "response_risk": "medium", "rollback": "Re-enable after review",
         "expected": "Pivoting via account stopped."},
        {"action": "Isolate affected hosts", "target_field": "host",
         "response_risk": "high", "rollback": "Restore network connectivity",
         "expected": "Movement between hosts contained."},
    ],
    "malware_execution": [
        {"action": "Isolate endpoint", "target_field": "host",
         "response_risk": "high", "rollback": "Restore network connectivity",
         "expected": "Infected host contained."},
        {"action": "Terminate suspicious process", "target_field": "process",
         "response_risk": "medium", "rollback": "N/A",
         "expected": "Malware process killed."},
    ],
    "anomalous_behaviour": [
        {"action": "Collect additional evidence", "target_field": None,
         "response_risk": "low", "rollback": "N/A (non-intrusive)",
         "expected": "More context gathered before acting."},
    ],
}

DEFAULT_PLAN = {"action": "Collect additional evidence", "target_field": None,
                "response_risk": "low", "rollback": "N/A (non-intrusive)",
                "expected": "More context gathered before acting."}


def _target_value(ctx: IncidentContext, field: str | None) -> str:
    if not field:
        return "incident scope"
    mapping = {
        "source_ip": ctx.source_ips,
        "destination_ip": ctx.destination_ips,
        "user": ctx.users,
        "host": ctx.hosts,
    }
    if field == "process":
        procs = {e.get("process") for e in ctx.events if e.get("process")}
        return next(iter(procs), "unknown process")
    values = mapping.get(field, set())
    return next(iter(v for v in values if v), "unknown")


# Transparent scoring weights (documented in docs/adaptive_learning.md).
SCORE_WEIGHTS = {
    "historical_success": 0.25,
    "memory_trust": 0.15,
    "current_confidence": 0.20,
    "agent_agreement": 0.15,
    "response_risk": 0.15,
    "rollback": 0.10,
}
RESP_RISK_SCORE = {"low": 1.0, "medium": 0.6, "high": 0.3}


def _score_candidate(plan: dict, *, current_confidence: float,
                     agent_agreement: float,
                     stats_by_action: dict) -> dict:
    """Compute a transparent recommendation score for one candidate response.

    Every component is a real value (0..1); nothing is hard-coded. The weighted
    sum is the recommendation confidence, and the components are returned so the
    UI can explain exactly why a candidate was preferred.
    """
    st = stats_by_action.get(plan["action"].lower())
    historical_success = st["success_rate"] if st else 0.5   # 0.5 = no history
    memory_trust = st["trust_score"] if st else 0.5
    rr = RESP_RISK_SCORE.get((plan.get("response_risk") or "low").lower(), 0.5)
    rollback = 1.0 if (plan.get("rollback") and
                       plan["rollback"].strip().lower() not in ("", "none")) else 0.3

    components = {
        "historical_success": round(historical_success, 3),
        "memory_trust": round(memory_trust, 3),
        "current_confidence": round(current_confidence, 3),
        "agent_agreement": round(agent_agreement, 3),
        "response_risk": round(rr, 3),
        "rollback": round(rollback, 3),
    }
    score = sum(SCORE_WEIGHTS[k] * v for k, v in components.items())
    return {
        "components": components,
        "has_history": bool(st),
        "recommendation_confidence": round(score, 3),
    }


def _score_reason(plan: dict) -> str:
    c = plan["score"]["components"]
    bits = []
    if plan["score"]["has_history"]:
        bits.append(f"validated historical success "
                    f"{int(c['historical_success']*100)}%")
    bits.append(f"evidence confidence {int(c['current_confidence']*100)}%")
    bits.append(f"agent agreement {int(c['agent_agreement']*100)}%")
    bits.append(f"{plan['response_risk']}-risk action")
    if c["rollback"] >= 1.0:
        bits.append("reversible (rollback available)")
    return "This response is preferred because: " + ", ".join(bits) + "."


def plan(ctx: IncidentContext, memory_recommendation: dict | None = None, *,
         current_confidence: float | None = None,
         agent_agreement: float = 0.5,
         attack_stats: list | None = None) -> list[dict]:
    """Generate scored candidate responses and pick the highest-scoring one.

    ``attack_stats`` is ``memory_agent.strategy_stats(attack_type)`` — measured,
    validated historical outcomes that drive adaptive selection.
    """
    templates = PLAYBOOK.get(ctx.attack_type, [DEFAULT_PLAN])
    evidence_summary = (f"{ctx.event_count} correlated events; "
                        f"{ctx.detection_reason}")
    if current_confidence is None:
        current_confidence = ctx.confidence
    stats_by_action = {s["strategy"].lower(): s for s in (attack_stats or [])}
    plans = []
    for t in templates:
        plans.append({
            "action": t["action"],
            "target": _target_value(ctx, t["target_field"]),
            "reason": (f"Mitigate {ctx.attack_type.replace('_', ' ')} "
                       f"(severity {ctx.severity})."),
            "evidence_summary": evidence_summary,
            "response_risk": t["response_risk"],
            "expected_outcome": t["expected"],
            "rollback": t["rollback"],
            "recommended": False,
        })

    # Transparent adaptive scoring for every candidate.
    for p in plans:
        p["score"] = _score_candidate(
            p, current_confidence=current_confidence,
            agent_agreement=agent_agreement, stats_by_action=stats_by_action)

    # The recommended response is the highest-scoring candidate (ties broken by
    # lower response risk). The score already rewards validated history, trust,
    # confidence, agreement, low risk and rollback — no black-box choice.
    risk_order = {"low": 0, "medium": 1, "high": 2}
    chosen = max(range(len(plans)), key=lambda i: (
        plans[i]["score"]["recommendation_confidence"],
        -risk_order.get(plans[i]["response_risk"], 3)))
    plans[chosen]["recommended"] = True
    plans[chosen]["reason"] = _score_reason(plans[chosen])
    if memory_recommendation and plans[chosen]["score"]["has_history"]:
        plans[chosen]["reason"] += (
            f" Historically effective "
            f"({int(memory_recommendation['effectiveness']*100)}%).")
    return plans
