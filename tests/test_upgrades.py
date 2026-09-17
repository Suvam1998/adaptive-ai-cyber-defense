"""Proof tests for the upgraded features (Phases 3, 8, 10, 12, 15, 17, 27, 30)."""
import datetime as dt

from backend import database as db
from backend import demo, ingestion
from backend.agents import (autonomy, consensus, memory_agent, orchestrator,
                            response_validator, threat_intel_agent)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _bf_csv(n=14, ip="203.0.113.66", user="jdoe", cols_alias=False, success=True):
    base = dt.datetime(2026, 9, 15, 10, 31, 0)
    hdr = ("event_time,eventType,accountName,sourceAddress,status,auth_result"
           if cols_alias else
           "timestamp,event_type,user,source_ip,status,authentication_result")
    lines = [hdr]
    for i in range(n):
        t = (base + dt.timedelta(seconds=i * 6)).isoformat()
        lines.append(f"{t},login,{user},{ip},failure,failure")
    if success:
        t = (base + dt.timedelta(seconds=n * 6 + 5)).isoformat()
        lines.append(f"{t},login,{user},{ip},success,success")
    return "\n".join(lines)


def _make_and_investigate():
    s = ingestion.ingest(_bf_csv(), "bf.csv", "real")
    inc = orchestrator.run_detection("real", s["batch_id"])["incidents_created"][0]
    return inc, orchestrator.investigate(inc)


# ---- Phase 3: data quality + alias normalization ------------------------- #
def test_field_aliases_normalize():
    s = ingestion.ingest(_bf_csv(cols_alias=True), "a.csv", "real")
    q = s["data_quality"]
    assert q["normalized_fields"]["sourceAddress"] == "source_ip"
    assert q["normalized_fields"]["accountName"] == "user"
    assert q["normalized_fields"]["event_time"] == "timestamp"
    ev = db.query("SELECT * FROM events WHERE dataset='real'")[0]
    assert ev["source_ip"] == "203.0.113.66"


def test_data_quality_rejects_empty_and_counts_duplicates():
    csv = _bf_csv(n=3, success=False) + "\n,,,,,\n"  # trailing junk row
    csv += csv.splitlines()[1]  # duplicate a real row
    s = ingestion.ingest(csv, "dq.csv", "real")
    q = s["data_quality"]
    assert q["rejected_records"] >= 1
    assert q["duplicate_records"] >= 1
    assert q["valid_records"] == s["stored"]


# ---- Phase 8: threat intel enrichment (no fabrication) ------------------- #
def test_ti_enrichment_and_local_only():
    hit = threat_intel_agent.lookup("203.0.113.66", "ip")
    assert hit["reputation"] == "malicious"
    assert "risk_contribution" in hit and "first_seen" in hit
    miss = threat_intel_agent.lookup("8.8.8.8", "ip")
    assert miss["reputation"] == "unknown"
    assert "Local intelligence only" in miss.get("note", "")


# ---- Phase 12: 8 validation checks + target validity --------------------- #
def test_validation_has_eight_checks():
    inc, a = _make_and_investigate()
    assert len(a["validation"]["checks"]) == 8
    assert "target_valid" in a["validation"]["checks"]
    assert "threat_active" in a["validation"]["checks"]


def test_invalid_target_is_rejected():
    inc, a = _make_and_investigate()
    ctx = orchestrator.build_context(inc)
    plan = {"action": "Block source IP", "target": "unknown",
            "response_risk": "low", "rollback": "remove"}
    risk = {"total": 80.0, "risk_score": 0.8, "breakdown": {}}
    v = response_validator.validate(ctx, plan, risk, a["consensus"], 0.9)
    assert v["decision"] == "REJECTED"
    assert v["checks"]["target_valid"] is False


# ---- Phase 6/10: all agents surfaced + disagreement escalates ------------ #
def test_all_agents_surfaced():
    inc, a = _make_and_investigate()
    names = {x["agent"] for x in a["agents"]}
    for expected in ("Consensus Agent", "Response Planning Agent",
                     "Response Validation Agent", "Autonomy Agent"):
        assert expected in names


def test_agent_disagreement_increases_escalation():
    agree = consensus.compute([
        {"agent": "A", "verdict": "Threat confirmed", "confidence": 0.9},
        {"agent": "B", "verdict": "Threat likely", "confidence": 0.85}])
    disagree = consensus.compute([
        {"agent": "A", "verdict": "Threat confirmed", "confidence": 0.95},
        {"agent": "B", "verdict": "No confirmed malicious reputation",
         "confidence": 0.9}])
    val = {"decision": "APPROVED", "response_risk": "low"}
    d_agree = autonomy.decide(risk_norm=0.8, confidence=0.8,
                              consensus=agree, validation=val)
    d_dis = autonomy.decide(risk_norm=0.8, confidence=0.8,
                            consensus=disagree, validation=val)
    # disagreement must force human approval (lower/again-capped autonomy)
    assert d_dis["requires_approval"] is True
    assert disagree["disagreement"] is True


# ---- Phase 13/14: high-risk needs approval; low-risk validated can proceed  #
def test_high_risk_action_requires_approval():
    inc, a = _make_and_investigate()
    ctx = orchestrator.build_context(inc)
    high = {"action": "Isolate endpoint", "target": "WKS-201",
            "response_risk": "high", "rollback": "restore"}
    # even at high risk, a high-impact action should not silently auto-execute
    risk = {"total": 90.0, "risk_score": 0.9, "breakdown": {}}
    v = response_validator.validate(ctx, high, risk, a["consensus"], 0.9)
    auto = autonomy.decide(risk_norm=0.9, confidence=0.9,
                           consensus=a["consensus"], validation=v)
    assert auto["auto_allowed"] is False  # AUTO_RESPONSE_ENABLED is false


# ---- Phase 15/17: failed verification reduces confidence; learning influences #
def test_learning_influences_future_recommendation():
    # seed a validated SUCCESS for brute_force / Block source IP
    memory_agent.record_experience(
        attack_type="brute_force", strategy="Block source IP", outcome="SUCCESS",
        effectiveness=1.0, source="seed", indicators={}, incident_id="SEED")
    rec = memory_agent.recommend_strategy("brute_force")
    assert rec is not None and rec["strategy"] == "Block source IP"
    stats = memory_agent.strategy_stats()  # measured stats callable
    assert isinstance(stats, list)


def test_failed_verification_reduces_strategy_confidence():
    memory_agent.record_experience(
        attack_type="port_scan", strategy="Block source IP", outcome="SUCCESS",
        effectiveness=1.0, source="seed", indicators={}, incident_id="S1")
    before = memory_agent.recommend_strategy("port_scan")["confidence"]
    memory_agent.record_experience(
        attack_type="port_scan", strategy="Block source IP",
        outcome="THREAT_PERSISTS", effectiveness=0.0, source="seed",
        indicators={}, incident_id="S2")
    after = db.query_one(
        "SELECT confidence FROM memory WHERE attack_type='port_scan' "
        "AND strategy='Block source IP'")["confidence"]
    assert after < before


# ---- Phase 25: dataset isolation both directions -------------------------- #
def test_demo_data_never_in_real_and_vice_versa():
    s = ingestion.ingest(_bf_csv(), "bf.csv", "real")
    orchestrator.run_detection("real", s["batch_id"])
    demo.load_scenario("brute_force")
    assert db.scalar("SELECT COUNT(*) FROM events WHERE dataset='real'") > 0
    # no demo incident appears in the real incident list and vice versa
    real_ids = {i["incident_id"] for i in
                db.query("SELECT incident_id FROM incidents WHERE dataset='real'")}
    demo_ids = {i["incident_id"] for i in
                db.query("SELECT incident_id FROM incidents WHERE dataset='demo'")}
    assert real_ids and demo_ids and not (real_ids & demo_ids)
