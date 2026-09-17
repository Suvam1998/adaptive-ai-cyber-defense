"""Incident Memory Agent — historical memory, adaptive learning, trusted memory.

Responsibilities
----------------
* recall similar past incidents to inform the current investigation
* recommend a response strategy from *validated* past outcomes
* after response verification, update learned confidence (up on success, down
  on failure) — but only from validated outcomes, never blindly
* enforce trusted memory: experiences are trusted / under_review / revoked, and
  REVOKED experiences never influence recommendations (memory-poisoning guard)

Every stored experience keeps provenance so its origin is auditable, and the
system always distinguishes HISTORICAL evidence from CURRENT evidence.
"""
from __future__ import annotations

from .. import audit
from .. import database as db
from ..models import new_experience_id, now_iso
from .context import IncidentContext

# EWMA factor for learning from a new validated outcome.
LEARN_ALPHA = 0.4


def similar_incidents(attack_type: str, exclude_id: str | None = None,
                      limit: int = 5) -> list[dict]:
    rows = db.query(
        "SELECT incident_id, created_at, attack_type, severity, risk_score, "
        "recommended_action, status FROM incidents WHERE attack_type=? "
        "AND incident_id != ? ORDER BY created_at DESC LIMIT ?",
        (attack_type, exclude_id or "", limit),
    )
    return rows


def trusted_experiences(attack_type: str) -> list[dict]:
    return db.query(
        "SELECT * FROM memory WHERE attack_type=? AND validation_status='trusted' "
        "ORDER BY (confidence*trust_score) DESC, effectiveness DESC",
        (attack_type,),
    )


def recommend_strategy(attack_type: str) -> dict | None:
    """Return the best validated strategy for this attack type, if any."""
    exps = trusted_experiences(attack_type)
    if not exps:
        return None
    best = exps[0]
    if (best["confidence"] or 0) * (best["trust_score"] or 0) < 0.35:
        return None
    return {
        "strategy": best["strategy"],
        "confidence": round(best["confidence"], 2),
        "trust_score": round(best["trust_score"], 2),
        "effectiveness": round(best["effectiveness"] or 0, 2),
        "experience_id": best["experience_id"],
        "source": best["source"],
    }


def assess(ctx: IncidentContext) -> dict:
    sims = similar_incidents(ctx.attack_type, ctx.incident_id)
    rec = recommend_strategy(ctx.attack_type)
    if rec:
        rationale = (f"{len(sims)} similar historical incident(s). Previously, "
                     f"'{rec['strategy']}' was effective "
                     f"({int(rec['effectiveness']*100)}% effectiveness, "
                     f"learned confidence {rec['confidence']}).")
        verdict = f"Similar incidents mitigated by: {rec['strategy']}"
        conf = min(0.9, 0.5 + rec["confidence"] / 2)
    elif sims:
        rationale = (f"{len(sims)} similar historical incident(s) found; no "
                     f"validated winning strategy yet.")
        verdict = "Historical precedent exists"
        conf = 0.55
    else:
        rationale = "No similar historical incidents in memory."
        verdict = "No historical precedent"
        conf = 0.4
    return {
        "agent": "Incident Memory Agent",
        "verdict": verdict,
        "confidence": round(conf, 2),
        "rationale": rationale,        # HISTORICAL evidence (kept distinct)
        "evidence_refs": [],
        "similar_incidents": sims,
        "recommendation": rec,
    }


def record_experience(*, attack_type: str, strategy: str, outcome: str,
                      effectiveness: float, source: str, indicators: dict,
                      analyst_decision: str = "", incident_id: str = "") -> dict:
    """Learn from a VALIDATED outcome. Updates existing experience or creates one.

    Only call this AFTER response verification — we do not learn from unvalidated
    incidents.
    """
    row = db.query_one(
        "SELECT * FROM memory WHERE attack_type=? AND strategy=? "
        "AND validation_status!='revoked'",
        (attack_type, strategy),
    )
    success = outcome == "SUCCESS"
    now = now_iso()
    if row:
        old_conf = row["confidence"] or 0.5
        target = 0.95 if success else 0.15
        new_conf = round((1 - LEARN_ALPHA) * old_conf + LEARN_ALPHA * target, 3)
        old_eff = row["effectiveness"] or 0.0
        new_eff = round((1 - LEARN_ALPHA) * old_eff + LEARN_ALPHA * effectiveness, 3)
        # trust nudges up slowly on repeated validated success
        new_trust = round(min(1.0, (row["trust_score"] or 0.5)
                              + (0.05 if success else -0.1)), 3)
        db.execute(
            "UPDATE memory SET confidence=?, effectiveness=?, trust_score=?, "
            "outcome=?, updated_at=?, analyst_decision=? WHERE experience_id=?",
            (new_conf, new_eff, new_trust, outcome, now,
             analyst_decision or row["analyst_decision"], row["experience_id"]),
        )
        exp_id = row["experience_id"]
        action = "memory.updated"
    else:
        exp_id = new_experience_id()
        db.insert("memory", {
            "experience_id": exp_id,
            "attack_type": attack_type,
            "indicators": db.jdump(indicators),
            "strategy": strategy,
            "outcome": outcome,
            "effectiveness": round(effectiveness, 3),
            "confidence": 0.7 if success else 0.3,
            "trust_score": 0.6 if success else 0.4,
            "validation_status": "trusted",
            "source": source,
            "provenance": db.jdump({"incident_id": incident_id, "source": source,
                                    "recorded_at": now, "validated": True}),
            "analyst_decision": analyst_decision,
            "created_at": now,
            "updated_at": now,
        })
        action = "memory.created"
    audit.log(action, incident_id=incident_id, actor="Incident Memory Agent",
              detail=f"{attack_type} / {strategy} -> {outcome}", dataset=source)
    return {"experience_id": exp_id, "outcome": outcome}


def set_trust(experience_id: str, status: str) -> bool:
    if status not in ("trusted", "under_review", "revoked"):
        return False
    exists = db.query_one("SELECT id FROM memory WHERE experience_id=?",
                          (experience_id,))
    if not exists:
        return False
    db.execute("UPDATE memory SET validation_status=?, updated_at=? "
               "WHERE experience_id=?", (status, now_iso(), experience_id))
    audit.log("memory.trust_changed", actor="analyst",
              detail=f"{experience_id} -> {status}")
    return True


def all_experiences() -> list[dict]:
    return db.query("SELECT * FROM memory ORDER BY updated_at DESC")


def strategy_stats(attack_type: str | None = None) -> list[dict]:
    """Measured per-(attack_type, strategy) success rates from VERIFIED outcomes.

    This is the ground-truth evidence behind adaptive learning: it is computed
    from actual response_outcomes, not from a label. The Response Planner uses
    the learned ``memory.confidence`` (updated from these outcomes) to rank
    candidate responses, so a strategy that verified successfully in the past is
    preferred for similar future incidents.
    """
    sql = (
        "SELECT i.attack_type, r.action AS strategy, "
        "COUNT(*) AS attempts, "
        "SUM(CASE WHEN o.outcome='SUCCESS' THEN 1 ELSE 0 END) AS successes, "
        "AVG(o.effectiveness) AS avg_effectiveness "
        "FROM response_outcomes o "
        "JOIN responses r ON o.response_id=r.response_id "
        "JOIN incidents i ON o.incident_id=i.incident_id "
    )
    params: list = []
    if attack_type:
        sql += "WHERE i.attack_type=? "
        params.append(attack_type)
    sql += "GROUP BY i.attack_type, r.action ORDER BY attempts DESC"
    rows = db.query(sql, params)
    # attach the learned confidence / trust from the memory store
    mem = {(m["attack_type"], m["strategy"]): m for m in all_experiences()}
    out = []
    for r in rows:
        attempts = r["attempts"] or 0
        succ = r["successes"] or 0
        m = mem.get((r["attack_type"], r["strategy"]), {})
        out.append({
            "attack_type": r["attack_type"],
            "strategy": r["strategy"],
            "attempts": attempts,
            "successes": succ,
            "success_rate": round(succ / attempts, 2) if attempts else 0.0,
            "avg_effectiveness": round(r["avg_effectiveness"] or 0.0, 2),
            "learned_confidence": round(m.get("confidence") or 0.0, 2),
            "trust_score": round(m.get("trust_score") or 0.0, 2),
            "validation_status": m.get("validation_status", "n/a"),
        })
    return out
