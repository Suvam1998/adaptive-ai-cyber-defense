"""Adaptive autonomy decision.

Levels
  0 Observe only
  1 Recommend
  2 Require human approval
  3 Automatically execute low-risk actions
  4 Controlled autonomous response

The level is derived from risk, confidence, evidence quality, agent agreement,
the response's own risk, and validation outcome — then CAPPED by
``config.AUTONOMY_LEVEL`` and ``config.AUTO_RESPONSE_ENABLED``. Destructive /
high-risk actions are never auto-executed.
"""
from __future__ import annotations

from ..config import config

LEVEL_NAMES = {
    0: "Observe only",
    1: "Recommend",
    2: "Human approval required",
    3: "Auto-execute low-risk action",
    4: "Controlled autonomous response",
}


def decide(*, risk_norm: float, confidence: float, consensus: dict,
           validation: dict) -> dict:
    agreement = consensus.get("agreement", 0.0)
    resp_risk = validation.get("response_risk", "low")
    decision = validation.get("decision")

    reasons = []

    if decision == "REJECTED":
        level = 1
        reasons.append("validation rejected the plan")
    elif consensus.get("disagreement"):
        level = 2
        reasons.append("agents disagree significantly")
    elif decision == "APPROVED" and resp_risk == "low" and risk_norm >= 0.7 \
            and confidence >= 0.75 and agreement >= 0.75:
        level = 3
        reasons.append("high risk+confidence+agreement, low-risk action")
    elif confidence < 0.6 or agreement < 0.6:
        level = 2
        reasons.append("insufficient confidence/agreement for automation")
    elif resp_risk in ("medium", "high"):
        level = 2
        reasons.append(f"{resp_risk}-risk action requires human approval")
    else:
        level = 2
        reasons.append("default to human approval")

    # Governance caps.
    effective = min(level, config.AUTONOMY_LEVEL)
    if effective != level:
        reasons.append(f"capped by AUTONOMY_LEVEL={config.AUTONOMY_LEVEL}")

    auto_allowed = (effective >= 3 and config.AUTO_RESPONSE_ENABLED
                    and decision == "APPROVED" and resp_risk == "low")
    if effective >= 3 and not config.AUTO_RESPONSE_ENABLED:
        reasons.append("AUTO_RESPONSE_ENABLED=false -> human approval enforced")

    if auto_allowed:
        outcome = "AUTO_RESPONSE_ALLOWED"
    else:
        outcome = "HUMAN_APPROVAL_REQUIRED"

    return {
        "level": effective,
        "level_name": LEVEL_NAMES[effective],
        "outcome": outcome,
        "auto_allowed": auto_allowed,
        "requires_approval": not auto_allowed,
        "reasons": reasons,
    }
