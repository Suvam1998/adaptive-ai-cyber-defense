"""SOC Orchestrator.

Central coordinator that drives the incident lifecycle:

    Detection -> Incident creation -> Investigation -> Evidence collection ->
    Risk assessment -> Response planning -> Validation -> Autonomy decision ->
    (Human approval | Safe simulation) -> Verification -> Learning

It maintains incident state and writes an audit entry for every meaningful step.
"""
from __future__ import annotations

from .. import audit
from .. import database as db
from .. import response_exec
from ..detection import anomaly, rules
from ..models import new_incident_id, new_response_id, now_iso
from ..security import event_injection_signals
from . import (autonomy, consensus, correlation_agent, detection_agent,
               investigation_agent, memory_agent, response_planner,
               response_validator, risk_agent, threat_intel_agent)
from .context import IncidentContext

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# Detection -> incident creation
# --------------------------------------------------------------------------- #
def run_detection(dataset: str = "real", batch_id: str | None = None) -> dict:
    if batch_id:
        events = db.query(
            "SELECT * FROM events WHERE dataset=? AND batch_id=? ORDER BY timestamp",
            (dataset, batch_id))
    else:
        events = db.query(
            "SELECT * FROM events WHERE dataset=? ORDER BY timestamp", (dataset,))
    if not events:
        return {"detections": 0, "incidents_created": [], "events_scanned": 0,
                "message": "No events to analyse."}

    detections = rules.run_rules(events)
    covered = {eid for d in detections for eid in d.event_ids}
    detections.extend(anomaly.detect_anomalies(events, covered))

    events_by_id = {e["id"]: e for e in events}
    created = []
    for det in detections:
        inc_id = _create_incident(det, events_by_id, dataset)
        if inc_id:
            created.append(inc_id)

    audit.log("detection.run",
              detail=f"Scanned {len(events)} events, {len(detections)} detections, "
                     f"{len(created)} new incidents.", dataset=dataset)
    return {
        "detections": len(detections),
        "incidents_created": created,
        "events_scanned": len(events),
    }


def _open_incident_with_key(dataset: str, key: str) -> dict | None:
    return db.query_one(
        "SELECT * FROM incidents WHERE dataset=? AND status NOT IN "
        "('Closed','Contained') AND detection_reason LIKE ? "
        "ORDER BY created_at DESC LIMIT 1",
        (dataset, f"%[{key}]%"),
    )


def _create_incident(det: rules.Detection, events_by_id: dict,
                     dataset: str) -> str | None:
    key = det.correlation_key or det.attack_type
    # Correlate: fold new events into an existing open incident with same key.
    existing = _open_incident_with_key(dataset, key)
    now = now_iso()
    evs = [events_by_id[i] for i in det.event_ids if i in events_by_id]
    injection = []
    for e in evs:
        injection.extend(event_injection_signals(e))

    if existing:
        _attach_events(existing["incident_id"], det, evs)
        db.execute("UPDATE incidents SET updated_at=?, evidence_count="
                   "(SELECT COUNT(*) FROM evidence WHERE incident_id=? AND kind='event') "
                   "WHERE incident_id=?",
                   (now, existing["incident_id"], existing["incident_id"]))
        return None  # not a *new* incident

    inc_id = new_incident_id()
    db.insert("incidents", {
        "incident_id": inc_id,
        "dataset": dataset,
        "created_at": now,
        "updated_at": now,
        "status": "New",
        "stage": "Detection",
        "severity": det.severity,
        "risk_score": 0.0,
        "confidence": det.confidence,
        "consensus": 0.0,
        "attack_type": det.attack_type,
        "detection_reason": f"{det.reason} [{key}]",
        "affected_hosts": db.jdump(sorted(h for h in det.hosts if h)),
        "affected_users": db.jdump(sorted(u for u in det.users if u)),
        "source_ips": db.jdump(sorted(s for s in det.source_ips if s)),
        "destination_ips": db.jdump(sorted(d for d in det.destination_ips if d)),
        "mitre": db.jdump(det.mitre()),
        "evidence_count": len(evs),
        "recommended_action": "Pending investigation",
        "autonomy_level": 1,
        "autonomy_decision": "Recommend",
        "anomaly_score": det.anomaly_score,
        "detection_method": det.detector,   # 'rule' | 'anomaly'
    })
    _attach_events(inc_id, det, evs)
    if injection:
        db.insert("evidence", {
            "incident_id": inc_id, "event_ref": None, "kind": "signal",
            "label": "Prompt-injection / instruction text in log payload",
            "detail": f"Markers (treated as DATA only): {', '.join(sorted(set(injection))[:6])}",
            "weight": 0.2, "created_at": now})
    if det.detector == "anomaly" and det.extra.get("signals"):
        db.insert("evidence", {
            "incident_id": inc_id, "event_ref": None, "kind": "signal",
            "label": f"Anomaly explanation (model: {det.extra.get('model')})",
            "detail": (f"MODEL SCORE {det.extra.get('model_score')}. "
                       f"EXPLANATORY HEURISTICS (not the model's internal "
                       f"reasoning): {', '.join(det.extra['signals'])}."),
            "weight": det.anomaly_score, "created_at": now})
    audit.log("incident.created", incident_id=inc_id, actor="SOC Orchestrator",
              detail=f"{det.attack_type} — {det.reason}", dataset=dataset)
    return inc_id


def _attach_events(incident_id: str, det: rules.Detection, evs: list[dict]) -> None:
    now = now_iso()
    existing_refs = {
        r["event_ref"] for r in db.query(
            "SELECT event_ref FROM evidence WHERE incident_id=? AND kind='event'",
            (incident_id,))
    }
    for e in evs:
        if e["id"] in existing_refs:
            continue
        db.insert("evidence", {
            "incident_id": incident_id, "event_ref": e["id"], "kind": "event",
            "label": e.get("event_type") or "event",
            "detail": (e.get("raw_event") or "")[:500],
            "weight": det.confidence, "created_at": now})


# --------------------------------------------------------------------------- #
# Context assembly
# --------------------------------------------------------------------------- #
def build_context(incident_id: str) -> IncidentContext | None:
    inc = db.query_one("SELECT * FROM incidents WHERE incident_id=?", (incident_id,))
    if not inc:
        return None
    ev_refs = [r["event_ref"] for r in db.query(
        "SELECT event_ref FROM evidence WHERE incident_id=? AND kind='event' "
        "AND event_ref IS NOT NULL", (incident_id,))]
    events = []
    if ev_refs:
        placeholders = ",".join(["?"] * len(ev_refs))
        events = db.query(
            f"SELECT * FROM events WHERE id IN ({placeholders})", ev_refs)
    injection = []
    for e in events:
        injection.extend(event_injection_signals(e))
    return IncidentContext(
        incident_id=incident_id,
        dataset=inc["dataset"],
        attack_type=inc["attack_type"],
        severity=inc["severity"],
        detection_reason=inc["detection_reason"],
        confidence=inc["confidence"] or 0.0,
        anomaly_score=inc["anomaly_score"] or 0.0,
        events=events,
        source_ips=set(db.jload(inc["source_ips"], []) or []),
        destination_ips=set(db.jload(inc["destination_ips"], []) or []),
        users=set(db.jload(inc["affected_users"], []) or []),
        hosts=set(db.jload(inc["affected_hosts"], []) or []),
        injection_signals=sorted(set(injection)),
    )


# --------------------------------------------------------------------------- #
# Investigation
# --------------------------------------------------------------------------- #
def investigate(incident_id: str) -> dict | None:
    ctx = build_context(incident_id)
    if not ctx:
        return None
    dataset = ctx.dataset

    db.execute("UPDATE incidents SET status='Investigating', stage='Investigation', "
               "updated_at=? WHERE incident_id=?", (now_iso(), incident_id))
    audit.log("investigation.started", incident_id=incident_id,
              actor="SOC Orchestrator", dataset=dataset)

    # --- run agents ---
    a_det = detection_agent.assess(ctx)
    a_inv = investigation_agent.assess(ctx)
    a_ti = threat_intel_agent.assess(ctx)
    a_cor = correlation_agent.assess(ctx)
    a_mem = memory_agent.assess(ctx)
    audit.log("evidence.collected", incident_id=incident_id,
              actor="Investigation Agent",
              detail=f"{ctx.event_count} events, timeline built", dataset=dataset)

    agent_conf = round(
        (a_det["confidence"] + a_inv["confidence"] + a_cor["confidence"]) / 3, 3)

    a_risk = risk_agent.assess(ctx, agent_conf, a_ti)
    risk = a_risk["risk"]
    audit.log("risk.scored", incident_id=incident_id, actor="Risk Assessment Agent",
              detail=f"Risk {risk['total']}/100", dataset=dataset)

    all_assessments = [a_det, a_inv, a_ti, a_risk, a_mem]
    cons = consensus.compute(all_assessments)

    # persist agent assessments (replace previous)
    db.execute("DELETE FROM agent_assessments WHERE incident_id=?", (incident_id,))
    for a in all_assessments:
        db.insert("agent_assessments", {
            "incident_id": incident_id, "agent": a["agent"],
            "verdict": a["verdict"], "confidence": a["confidence"],
            "rationale": a["rationale"],
            "evidence_refs": db.jdump(a.get("evidence_refs", [])),
            "created_at": now_iso()})

    # --- response planning (adaptive, transparently scored) ---
    mem_rec = a_mem.get("recommendation")
    attack_stats = memory_agent.strategy_stats(ctx.attack_type)
    plans = response_planner.plan(
        ctx, mem_rec, current_confidence=agent_conf,
        agent_agreement=cons["agreement"], attack_stats=attack_stats)
    recommended = next(p for p in plans if p["recommended"])
    audit.log("response.planned", incident_id=incident_id,
              actor="Response Planning Agent",
              detail=f"{len(plans)} plan(s); recommended: {recommended['action']}",
              dataset=dataset)

    # --- validation of recommended plan ---
    validation = response_validator.validate(ctx, recommended, risk, cons, agent_conf)
    audit.log("response.validated", incident_id=incident_id,
              actor="Response Validation Agent",
              detail=validation["summary"][:300], dataset=dataset)

    # --- autonomy decision ---
    auto = autonomy.decide(risk_norm=risk["risk_score"], confidence=agent_conf,
                           consensus=cons, validation=validation)
    audit.log("autonomy.decided", incident_id=incident_id, actor="SOC Orchestrator",
              detail=f"{auto['outcome']} (level {auto['level']}: {auto['level_name']})",
              dataset=dataset)

    # --- surface Consensus / Planning / Validation / Autonomy as visible agents ---
    # (computed AFTER the consensus math, so they never pollute the consensus score)
    n_checks = len(validation["checks"])
    n_pass = sum(1 for v in validation["checks"].values() if v)
    display_only = [
        {"agent": "Consensus Agent",
         "verdict": f"Consensus {int(cons['score'] * 100)}% "
                    f"({'disagreement' if cons['disagreement'] else 'aligned'})",
         "confidence": cons["agreement"],
         "rationale": (f"Agreement {int(cons['agreement'] * 100)}% across "
                       f"{len(cons['stances'])} agents; "
                       f"mean belief {int(cons['mean_belief'] * 100)}%."),
         "evidence_refs": []},
        {"agent": "Response Planning Agent",
         "verdict": f"Recommend: {recommended['action']}",
         "confidence": agent_conf,
         "rationale": f"{recommended['reason']} (response risk "
                      f"{recommended['response_risk']}).",
         "evidence_refs": []},
        {"agent": "Response Validation Agent",
         "verdict": validation["decision"],
         "confidence": round(n_pass / n_checks, 2),
         "rationale": f"{n_pass}/{n_checks} safety checks passed. "
                      + validation["summary"][:200],
         "evidence_refs": []},
        {"agent": "Autonomy Agent",
         "verdict": auto["outcome"],
         "confidence": round(auto["level"] / 4.0, 2),
         "rationale": f"Level {auto['level']} ({auto['level_name']}): "
                      + "; ".join(auto["reasons"]),
         "evidence_refs": []},
    ]
    for a in display_only:
        db.insert("agent_assessments", {
            "incident_id": incident_id, "agent": a["agent"],
            "verdict": a["verdict"], "confidence": a["confidence"],
            "rationale": a["rationale"],
            "evidence_refs": db.jdump(a["evidence_refs"]), "created_at": now_iso()})

    # --- persist responses ---
    db.execute("DELETE FROM responses WHERE incident_id=? AND status IN "
               "('planned','validated','awaiting_approval')", (incident_id,))
    resp_ids = []
    recommended_response_id = None
    now = now_iso()
    for p in plans:
        rid = new_response_id()
        is_rec = p["recommended"]
        status = ("awaiting_approval" if is_rec and auto["requires_approval"]
                  else "validated" if is_rec else "planned")
        if is_rec and validation["decision"] == "REJECTED":
            status = "rejected"
        db.insert("responses", {
            "response_id": rid, "incident_id": incident_id,
            "action": p["action"], "target": p["target"], "reason": p["reason"],
            "evidence_summary": p["evidence_summary"],
            "response_risk": p["response_risk"],
            "expected_outcome": p["expected_outcome"], "rollback": p["rollback"],
            "status": status,
            "requires_approval": 1 if (is_rec and auto["requires_approval"]) else 0,
            "created_at": now, "updated_at": now})
        resp_ids.append(rid)
        if is_rec:
            db.insert("response_validation", {
                "response_id": rid, "incident_id": incident_id,
                "evidence_sufficient": int(validation["checks"]["evidence_sufficient"]),
                "confidence_ok": int(validation["checks"]["confidence_ok"]),
                "agents_agree": int(validation["checks"]["agents_agree"]),
                "proportional": int(validation["checks"]["proportional"]),
                "business_impact_ok": int(validation["checks"]["business_impact_ok"]),
                "rollback_ok": int(validation["checks"]["rollback_ok"]),
                "target_valid": int(validation["checks"]["target_valid"]),
                "threat_active": int(validation["checks"]["threat_active"]),
                "decision": validation["decision"],
                "detail": db.jdump(validation), "created_at": now})
            recommended_response_id = rid

    # --- update incident state ---
    new_status = ("Awaiting Approval" if auto["requires_approval"]
                  else "Investigating")
    if validation["decision"] == "REJECTED":
        new_status = "Investigating"
    stage = ("Human Approval" if auto["requires_approval"]
             else "Response Validation")
    # escalate severity if risk very high
    severity = ctx.severity
    if risk["total"] >= 85 and SEV_RANK.get(severity.lower(), 2) < 4:
        severity = "Critical"

    db.execute(
        "UPDATE incidents SET status=?, stage=?, severity=?, risk_score=?, "
        "confidence=?, consensus=?, recommended_action=?, autonomy_level=?, "
        "autonomy_decision=?, mitre=?, updated_at=? WHERE incident_id=?",
        (new_status, stage, severity, risk["risk_score"], agent_conf,
         cons["score"], recommended["action"], auto["level"],
         f"{auto['outcome']} — {auto['level_name']}",
         db.jdump(_mitre_for(ctx, a_ti)), now, incident_id))

    decision_explanation = _build_decision_explanation(
        ctx, risk, agent_conf, cons, recommended, validation, auto)

    analysis = {
        "incident_id": incident_id,
        "agents": all_assessments + display_only,
        "analysis_agents": all_assessments,   # the 5 that drive consensus
        "agent_confidence": agent_conf,
        "risk": risk,
        "consensus": cons,
        "plans": plans,
        "recommended_response_id": recommended_response_id,
        "recommended_action": recommended["action"],
        "validation": validation,
        "autonomy": auto,
        "decision_explanation": decision_explanation,
        "attack_chain": build_attack_chain(ctx),
        "memory": {"similar": a_mem.get("similar_incidents", []),
                   "recommendation": mem_rec},
        "generated_at": now,
    }
    _store_analysis(incident_id, analysis)
    return analysis


def _mitre_for(ctx: IncidentContext, ti: dict) -> list[dict]:
    from ..detection import mitre as m
    techs = m.techniques_for(ctx.attack_type, ctx.detection_reason, ctx.confidence)
    return techs


def _build_decision_explanation(ctx, risk, agent_conf, cons, recommended,
                                validation, auto) -> dict:
    """Human-readable 'Why this decision?' payload (Priority 5).

    Every field is a real value already computed in the investigation — this
    just assembles them and states the reasoning in plain language.
    """
    comp = recommended.get("score", {}).get("components", {})
    factors = {
        "risk": f"{risk['total']}/100",
        "evidence_confidence": f"{int(agent_conf * 100)}%",
        "agent_agreement": f"{int(cons['agreement'] * 100)}%",
        "historical_success": f"{int(comp.get('historical_success', 0.5) * 100)}%",
        "memory_trust": f"{comp.get('memory_trust', 0.5):.2f}",
        "response_risk": recommended.get("response_risk", "low").upper(),
        "rollback": "AVAILABLE" if comp.get("rollback", 0) >= 1.0 else "LIMITED",
        "autonomy_level": f"{auto['level']} ({auto['level_name']})",
        "human_approval_required": auto["requires_approval"],
        "validation_decision": validation["decision"],
    }
    if validation["decision"] == "REJECTED":
        reason = ("The proposed response failed one or more safety checks and was "
                  "rejected; human review is required before any action.")
    elif cons["disagreement"]:
        reason = ("Agents disagreed on this incident, so autonomy was reduced and "
                  "the decision is escalated to a human analyst.")
    elif auto["requires_approval"]:
        reason = (f"Evidence supports '{recommended['action']}', but because the "
                  f"action/risk profile is not low-risk-auto-eligible, human "
                  f"approval is required before the simulated response runs.")
    else:
        reason = (f"Strong evidence and agent agreement support "
                  f"'{recommended['action']}'. The action is low-risk and "
                  f"reversible, so it is eligible for automatic simulation.")
    return {
        "recommended_action": recommended["action"],
        "target": recommended["target"],
        "factors": factors,
        "score_components": comp,
        "recommendation_confidence":
            recommended.get("score", {}).get("recommendation_confidence"),
        "reason": reason,
    }


# Attack-stage templates: ordered logical stages per attack type. A stage only
# appears in the chain if the incident's events actually support it.
_CHAIN_STAGES = {
    "brute_force": ["source_ip", "auth_failures"],
    "credential_compromise": ["source_ip", "auth_failures", "auth_success",
                              "user", "host", "privileged", "process", "outbound"],
    "port_scan": ["source_ip", "scan", "host"],
    "suspicious_powershell": ["host", "user", "process"],
    "privilege_escalation": ["user", "host", "privileged"],
    "lateral_movement": ["user", "auth_success", "host"],
    "data_exfiltration": ["host", "user", "process", "outbound"],
    "malware_execution": ["host", "process", "outbound"],
    "anomalous_behaviour": ["source_ip", "host", "user"],
}


def build_attack_chain(ctx: IncidentContext) -> list[dict]:
    """Build an ordered attack chain from the incident's real events.

    Each stage node lists the supporting event ids; a stage is only included
    when the evidence supports it (no fabricated relationships).
    """
    from ..detection.rules import _is_failed_login, _is_success_login
    events = sorted(ctx.events, key=lambda e: str(e.get("timestamp") or ""))

    def _mk(label, predicate):
        ids = [e["id"] for e in events if predicate(e)]
        return {"label": label, "event_ids": ids, "count": len(ids)} if ids else None

    builders = {
        "source_ip": lambda: ({"label": f"Source IP: {next(iter(ctx.source_ips))}",
                               "event_ids": [e["id"] for e in events
                                             if e.get("source_ip")],
                               "count": sum(1 for e in events if e.get("source_ip"))}
                              if ctx.source_ips else None),
        "auth_failures": lambda: _mk("Failed authentication", _is_failed_login),
        "auth_success": lambda: _mk("Successful authentication", _is_success_login),
        "user": lambda: ({"label": f"User: {next(iter(ctx.users))}",
                          "event_ids": [e["id"] for e in events if e.get("user")],
                          "count": sum(1 for e in events if e.get("user"))}
                         if ctx.users else None),
        "host": lambda: ({"label": f"Host: {next(iter(ctx.hosts))}",
                          "event_ids": [e["id"] for e in events if e.get("host")],
                          "count": sum(1 for e in events if e.get("host"))}
                         if ctx.hosts else None),
        "privileged": lambda: _mk("Privileged activity", lambda e:
                                  "priv" in (e.get("event_type") or "").lower()
                                  or any(k in (e.get("command") or "").lower()
                                         for k in ("whoami /priv", "admin", "runas",
                                                   "sudo", "net localgroup"))),
        "process": lambda: _mk("Process / script execution", lambda e:
                               bool(e.get("process") or e.get("command"))),
        "scan": lambda: _mk("Port / service scan", lambda e:
                            e.get("port") is not None
                            or "scan" in (e.get("event_type") or "").lower()
                            or "connection" in (e.get("event_type") or "").lower()),
        "outbound": lambda: _mk("Outbound connection", lambda e:
                                bool(e.get("destination_ip")) or (e.get("bytes") or 0) > 0),
    }
    chain = []
    for stage in _CHAIN_STAGES.get(ctx.attack_type, ["source_ip", "host", "user"]):
        node = builders.get(stage, lambda: None)()
        if node:
            chain.append(node)
    return chain


def _store_analysis(incident_id: str, analysis: dict) -> None:
    db.execute("DELETE FROM evidence WHERE incident_id=? AND kind='analysis'",
               (incident_id,))
    db.insert("evidence", {
        "incident_id": incident_id, "event_ref": None, "kind": "analysis",
        "label": "investigation_analysis", "detail": db.jdump(analysis),
        "weight": 0.0, "created_at": now_iso()})


def get_analysis(incident_id: str) -> dict | None:
    row = db.query_one(
        "SELECT detail FROM evidence WHERE incident_id=? AND kind='analysis' "
        "ORDER BY id DESC LIMIT 1", (incident_id,))
    if not row:
        return None
    return db.jload(row["detail"])


# --------------------------------------------------------------------------- #
# Response lifecycle
# --------------------------------------------------------------------------- #
def approve_response(response_id: str, analyst: str = "analyst") -> dict | None:
    resp = db.query_one("SELECT * FROM responses WHERE response_id=?", (response_id,))
    if not resp:
        return None
    if resp["status"] == "rejected":
        return {"error": "Response was rejected by validation and cannot be approved."}
    db.execute("UPDATE responses SET status='approved', requires_approval=0, "
               "updated_at=? WHERE response_id=?", (now_iso(), response_id))
    audit.log("response.approved", incident_id=resp["incident_id"], actor=analyst,
              detail=f"Human approval for {resp['action']} -> {resp['target']}",
              dataset=_dataset_of(resp["incident_id"]))
    return db.query_one("SELECT * FROM responses WHERE response_id=?", (response_id,))


def simulate_response(response_id: str, analyst: str = "analyst") -> dict | None:
    resp = db.query_one("SELECT * FROM responses WHERE response_id=?", (response_id,))
    if not resp:
        return None
    if resp["status"] == "rejected":
        return {"error": "Response was rejected by validation; simulation blocked."}
    dataset = _dataset_of(resp["incident_id"])

    if resp["requires_approval"] and resp["status"] not in ("approved",):
        return {"error": "Human approval required before simulation.",
                "requires_approval": True}

    before_events = response_exec.incident_events(resp["incident_id"], dataset)
    sim = response_exec.simulate(dict(resp), dataset, before_events)
    db.execute("UPDATE responses SET status='executed', updated_at=? "
               "WHERE response_id=?", (now_iso(), response_id))
    ver = response_exec.verify(dict(resp), dataset, before_events)

    # --- adaptive learning (only from this validated outcome) ---
    inc = db.query_one("SELECT * FROM incidents WHERE incident_id=?",
                       (resp["incident_id"],))
    memory_agent.record_experience(
        attack_type=inc["attack_type"], strategy=resp["action"],
        outcome=ver["outcome"], effectiveness=ver["effectiveness"],
        source=dataset,
        indicators={"source_ips": db.jload(inc["source_ips"], []),
                    "hosts": db.jload(inc["affected_hosts"], [])},
        analyst_decision="approved+simulated", incident_id=resp["incident_id"])

    # --- update incident state based on verification ---
    if ver["outcome"] == "SUCCESS":
        new_status, stage = "Contained", "Closed"
    elif ver["outcome"] == "PARTIAL":
        new_status, stage = "Investigating", "Follow-up"
    else:
        new_status, stage = "Investigating", "Follow-up Investigation"
        audit.log("incident.followup", incident_id=resp["incident_id"],
                  actor="SOC Orchestrator",
                  detail="Threat persists — follow-up investigation created.",
                  dataset=dataset)
    db.execute("UPDATE incidents SET status=?, stage=?, updated_at=? "
               "WHERE incident_id=?",
               (new_status, stage, now_iso(), resp["incident_id"]))

    return {"simulation": sim, "verification": ver, "outcome": ver["outcome"],
            "incident_status": new_status}


def revalidate_response(response_id: str) -> dict | None:
    resp = db.query_one("SELECT * FROM responses WHERE response_id=?", (response_id,))
    if not resp:
        return None
    analysis = get_analysis(resp["incident_id"])
    if analysis:
        return analysis["validation"]
    # fall back to fresh investigation
    a = investigate(resp["incident_id"])
    return a["validation"] if a else None


def _dataset_of(incident_id: str) -> str:
    row = db.query_one("SELECT dataset FROM incidents WHERE incident_id=?",
                       (incident_id,))
    return row["dataset"] if row else "real"
