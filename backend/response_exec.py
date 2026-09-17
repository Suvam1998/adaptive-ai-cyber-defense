"""Safe response execution (SIMULATION) and response verification.

Responses are NEVER executed against real systems. A simulated response records
its *effect as a predicate* in the ``response_effects`` table — it does not
touch the ``events`` table, so the original security evidence stays immutable
and forensically intact.

Verification is delegated to :mod:`backend.verification`, which is
attack-type-aware and computes the "after" state by applying the response
coverage predicate to the (unchanged) events.
"""
from __future__ import annotations

from . import audit
from . import database as db
from . import verification
from .models import now_iso


def incident_events(incident_id: str, dataset: str) -> list[dict]:
    """The events that constitute the incident's evidence (immutable)."""
    refs = [r["event_ref"] for r in db.query(
        "SELECT event_ref FROM evidence WHERE incident_id=? AND kind='event' "
        "AND event_ref IS NOT NULL", (incident_id,))]
    if not refs:
        return []
    placeholders = ",".join(["?"] * len(refs))
    return db.query(
        f"SELECT * FROM events WHERE id IN ({placeholders}) AND dataset=?",
        refs + [dataset])


def simulate(response: dict, dataset: str,
             before_events: list[dict] | None = None) -> dict:
    """Simulate a response. Records the effect predicate; mutates nothing."""
    incident_id = response["incident_id"]
    action = response["action"]
    target = response["target"]
    if before_events is None:
        before_events = incident_events(incident_id, dataset)

    _surviving, neutralised = verification.apply_effect(
        before_events, action, target)
    coverage = verification._coverage_dimension(action)

    effect_text = (
        f"SIMULATED: future activity matching {coverage}={target} would be "
        f"stopped ({len(neutralised)} current indicator event(s) covered)."
        if coverage != "none" else
        "SIMULATED: non-intrusive action; no enforcement effect modelled.")

    db.insert("response_effects", {
        "response_id": response["response_id"],
        "incident_id": incident_id,
        "action": action, "target": target,
        "effect": effect_text, "coverage": coverage,
        "neutralized_event_ids": db.jdump(neutralised),
        "neutralized_count": len(neutralised),
        "simulated": 1, "created_at": now_iso()})

    audit.log(
        "response.simulated", incident_id=incident_id,
        actor="Response Executor (SIMULATION)",
        detail=f"SIMULATED SUCCESS: {action} -> {target} "
               f"(effect recorded; {len(neutralised)} indicators covered; "
               f"original events unchanged)",
        dataset=dataset)
    return {
        "simulated": True,
        "action": action,
        "target": target,
        "coverage": coverage,
        "effect": effect_text,
        "neutralised": len(neutralised),
        "before_events": before_events,
        "message": "SIMULATED SUCCESS — original evidence unchanged",
    }


def verify(response: dict, dataset: str,
           before_events: list[dict] | None = None) -> dict:
    """Attack-specific verification; persists an enriched outcome record."""
    incident_id = response["incident_id"]
    incident = db.query_one("SELECT * FROM incidents WHERE incident_id=?",
                            (incident_id,))
    if before_events is None:
        before_events = incident_events(incident_id, dataset)

    result = verification.verify_response(
        incident, response["action"], response["target"], before_events)

    db.insert("response_outcomes", {
        "response_id": response["response_id"],
        "incident_id": incident_id,
        "indicators_before": result["total_before"],
        "indicators_after": result["total_after"],
        "outcome": result["outcome"],
        "effectiveness": result["effectiveness"],
        "detail": f"{result['verification_status']}: "
                  f"{result['total_before']} -> {result['total_after']}",
        "verification_method": result["verification_method"],
        "verification_confidence": result["verification_confidence"],
        "persistence_detected": int(result["persistence_detected"]),
        "evidence": db.jdump(result["evidence"]),
        "created_at": now_iso()})

    audit.log(
        "response.verified", incident_id=incident_id,
        actor="Response Executor (SIMULATION)",
        detail=f"Verification [{result['attack_type']}]: "
               f"{result['verification_status']} "
               f"(indicators {result['total_before']} -> {result['total_after']}, "
               f"persistence={result['persistence_detected']}, "
               f"confidence {result['verification_confidence']})",
        dataset=dataset)
    return result
