"""Response Validation Agent.

Runs eight safety checks before any response can proceed:

  1. Is the evidence sufficient?
  2. Is the incident confidence high enough?
  3. Do the agents agree?
  4. Is the action proportional to the risk?
  5. Could the action cause excessive business impact?
  6. Is rollback possible?
  7. Is the response target valid?
  8. Is the threat still active?

Returns APPROVED / NEEDS_APPROVAL / REJECTED plus the individual check results.
A REJECTED plan is never eligible for execution (even simulated auto-exec).
"""
from __future__ import annotations

from ..config import config

RESPONSE_RISK_RANK = {"low": 1, "medium": 2, "high": 3}


def validate(ctx, plan: dict, risk: dict, consensus: dict,
             agent_confidence: float) -> dict:
    risk_total = risk["total"]                # 0..100
    risk_norm = risk_total / 100.0
    resp_risk = (plan.get("response_risk") or "low").lower()

    # 1. evidence sufficient
    evidence_sufficient = (ctx.event_count >= 2 and ctx.confidence >= 0.5) \
        or ctx.event_count >= 5
    # 2. confidence high enough
    confidence_ok = agent_confidence >= 0.6 and ctx.confidence >= 0.5
    # 3. agents agree
    agents_agree = not consensus.get("disagreement") and consensus.get("agreement", 0) >= 0.5
    # 4. proportional: don't take a high-risk action for a low-risk incident
    if resp_risk == "high":
        proportional = risk_norm >= 0.65
    elif resp_risk == "medium":
        proportional = risk_norm >= 0.4
    else:
        proportional = True
    # 5. business impact acceptable: high-impact action needs strong evidence+agreement
    if resp_risk == "high":
        business_impact_ok = confidence_ok and agents_agree and risk_norm >= 0.65
    else:
        business_impact_ok = True
    # 6. rollback possible
    rollback = (plan.get("rollback") or "").strip().lower()
    rollback_ok = bool(plan.get("rollback")) and rollback not in ("", "none")
    # 7. target validity: an enforcement action needs a concrete target
    action_l = (plan.get("action") or "").lower()
    target = (plan.get("target") or "").strip()
    non_targeted = any(k in action_l for k in
                       ("collect", "monitor", "increase monitoring", "evidence"))
    target_valid = non_targeted or (
        target and target.lower() not in ("incident scope", "unknown", "none", ""))
    # 8. threat still active: are there indicators/events to act on?
    threat_active = ctx.event_count > 0

    checks = {
        "evidence_sufficient": evidence_sufficient,
        "confidence_ok": confidence_ok,
        "agents_agree": agents_agree,
        "proportional": proportional,
        "business_impact_ok": business_impact_ok,
        "rollback_ok": rollback_ok,
        "target_valid": target_valid,
        "threat_active": threat_active,
    }

    # Hard failures -> reject outright.
    hard_fail = (not evidence_sufficient) or (not proportional) \
        or (not business_impact_ok) or (not target_valid) or (not threat_active)
    if hard_fail:
        decision = "REJECTED"
    elif all(checks.values()) and risk_norm >= config.RISK_THRESHOLD \
            and resp_risk == "low" and consensus.get("agreement", 0) >= 0.6:
        decision = "APPROVED"          # eligible for (simulated) auto-response
    else:
        decision = "NEEDS_APPROVAL"

    reasons = []
    labels = {
        "evidence_sufficient": "evidence sufficiency",
        "confidence_ok": "incident confidence",
        "agents_agree": "agent agreement",
        "proportional": "proportionality to risk",
        "business_impact_ok": "acceptable business impact",
        "rollback_ok": "rollback availability",
        "target_valid": "response target validity",
        "threat_active": "threat still active",
    }
    for k, ok in checks.items():
        reasons.append(f"{labels[k]}: {'PASS' if ok else 'FAIL'}")

    return {
        "decision": decision,
        "checks": checks,
        "detail": reasons,
        "response_risk": resp_risk,
        "risk_total": risk_total,
        "summary": (f"{decision} — " + "; ".join(reasons)),
    }
