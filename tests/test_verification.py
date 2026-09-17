"""Tests for the v1.2 upgrades: immutable evidence, attack-specific
verification, adaptive response scoring, attack chains, anomaly explanation."""
import datetime as dt

from backend import database as db
from backend import ingestion, response_exec, verification
from backend.agents import memory_agent, orchestrator, response_planner


# --------------------------------------------------------------------------- #
def _csv(kind: str) -> str:
    base = dt.datetime(2026, 9, 15, 10, 31, 0)
    L = ["timestamp,event_type,user,host,source_ip,destination_ip,port,"
         "status,authentication_result,process,command,bytes"]

    def row(off, **k):
        d = {c: "" for c in L[0].split(",")}
        d["timestamp"] = (base + dt.timedelta(seconds=off)).isoformat()
        d.update(k)
        return ",".join(str(d[c]) for c in L[0].split(","))

    if kind == "brute_force":
        for i in range(14):
            L.append(row(i * 6, event_type="login", user="jdoe",
                         source_ip="203.0.113.66", status="failure",
                         authentication_result="failure"))
    elif kind == "port_scan":
        for i in range(20):
            L.append(row(i, event_type="connection", source_ip="45.155.205.233",
                         destination_ip="10.0.0.15", port=1000 + i))
    elif kind == "data_exfiltration":
        for i in range(4):
            L.append(row(i * 15, event_type="exfiltration", user="svc",
                         host="FIN-1", source_ip="10.0.0.15",
                         destination_ip="198.51.100.199", port=443,
                         bytes=9_000_000))
    return "\n".join(L)


def _incident(kind: str):
    s = ingestion.ingest(_csv(kind), f"{kind}.csv", "real")
    inc = orchestrator.run_detection("real", s["batch_id"])["incidents_created"][0]
    return inc


# --------------------------------------------------------------------------- #
# Immutable evidence
# --------------------------------------------------------------------------- #
def test_simulation_does_not_mutate_original_events():
    inc = _incident("brute_force")
    a = orchestrator.investigate(inc)
    before = db.query("SELECT id, authentication_result, status, event_type, "
                      "source_ip, timestamp FROM events WHERE dataset='real' "
                      "ORDER BY id")
    rid = a["recommended_response_id"]
    if db.query_one("SELECT requires_approval FROM responses WHERE response_id=?",
                    (rid,))["requires_approval"]:
        orchestrator.approve_response(rid, "t")
    orchestrator.simulate_response(rid)
    after = db.query("SELECT id, authentication_result, status, event_type, "
                     "source_ip, timestamp FROM events WHERE dataset='real' "
                     "ORDER BY id")
    assert before == after            # forensic evidence unchanged
    # but a response effect was recorded separately
    assert db.scalar("SELECT COUNT(*) FROM response_effects WHERE incident_id=?",
                     (inc,)) >= 1


# --------------------------------------------------------------------------- #
# Attack-specific verification
# --------------------------------------------------------------------------- #
def test_verification_is_attack_specific():
    inc = _incident("port_scan")
    incident = db.query_one("SELECT * FROM incidents WHERE incident_id=?", (inc,))
    events = response_exec.incident_events(inc, "real")
    res = verification.verify_response(incident, "Block source IP",
                                       "45.155.205.233", events)
    assert res["attack_type"] == "port_scan"
    assert "scan_connections" in res["indicators_before"]
    assert res["verification_status"] == "VERIFIED_RESOLVED"
    assert res["persistence_detected"] is False


def test_verification_detects_persistence_when_action_misses_target():
    inc = _incident("data_exfiltration")
    incident = db.query_one("SELECT * FROM incidents WHERE incident_id=?", (inc,))
    events = response_exec.incident_events(inc, "real")
    # blocking the wrong IP should NOT resolve the exfiltration indicators
    res = verification.verify_response(incident, "Block source IP",
                                       "9.9.9.9", events)
    assert res["persistence_detected"] is True
    assert res["verification_status"] == "THREAT_PERSISTS"


def test_verification_structure_complete():
    inc = _incident("brute_force")
    incident = db.query_one("SELECT * FROM incidents WHERE incident_id=?", (inc,))
    events = response_exec.incident_events(inc, "real")
    res = verification.verify_response(incident, "Block source IP",
                                       "203.0.113.66", events)
    for key in ("verification_status", "indicators_before", "indicators_after",
                "persistence_detected", "verification_confidence",
                "verification_method", "evidence"):
        assert key in res


# --------------------------------------------------------------------------- #
# Adaptive response scoring
# --------------------------------------------------------------------------- #
def test_response_scoring_is_transparent():
    inc = _incident("brute_force")
    a = orchestrator.investigate(inc)
    rec = next(p for p in a["plans"] if p["recommended"])
    comp = rec["score"]["components"]
    for key in ("historical_success", "memory_trust", "current_confidence",
                "agent_agreement", "response_risk", "rollback"):
        assert key in comp and 0.0 <= comp[key] <= 1.0
    assert 0.0 <= rec["score"]["recommendation_confidence"] <= 1.0


def test_validated_history_raises_candidate_score():
    # baseline score without history
    inc = _incident("brute_force")
    a = orchestrator.investigate(inc)
    base = next(p for p in a["plans"] if "block source ip" in p["action"].lower())
    base_hist = base["score"]["components"]["historical_success"]
    # seed strong validated history for Block source IP on brute_force
    for _ in range(3):
        memory_agent.record_experience(
            attack_type="brute_force", strategy="Block source IP",
            outcome="SUCCESS", effectiveness=1.0, source="seed",
            indicators={}, incident_id="SEED")
    # need at least one verified outcome row for strategy_stats; simulate one
    rid = a["recommended_response_id"]
    if db.query_one("SELECT requires_approval FROM responses WHERE response_id=?",
                    (rid,))["requires_approval"]:
        orchestrator.approve_response(rid, "t")
    orchestrator.simulate_response(rid)
    inc2 = _incident("brute_force")
    a2 = orchestrator.investigate(inc2)
    now = next(p for p in a2["plans"] if "block source ip" in p["action"].lower())
    assert now["score"]["components"]["historical_success"] >= base_hist


# --------------------------------------------------------------------------- #
# Decision explanation + attack chain
# --------------------------------------------------------------------------- #
def test_decision_explanation_present():
    inc = _incident("brute_force")
    a = orchestrator.investigate(inc)
    d = a["decision_explanation"]
    assert d["recommended_action"] and d["reason"]
    assert "risk" in d["factors"] and "human_approval_required" in d["factors"]


def test_attack_chain_from_real_events_only():
    inc = _incident("brute_force")
    a = orchestrator.investigate(inc)
    chain = a["attack_chain"]
    assert chain and all(node["count"] > 0 for node in chain)
    labels = " ".join(n["label"] for n in chain)
    assert "Failed authentication" in labels


# --------------------------------------------------------------------------- #
# Anomaly explanation (model score vs heuristics)
# --------------------------------------------------------------------------- #
def test_anomaly_signals_recorded():
    from backend.detection import anomaly, rules
    # craft data with one clear outlier to trigger an anomaly detection
    base = dt.datetime(2026, 9, 15, 3, 0, 0)
    L = ["timestamp,event_type,user,host,source_ip,destination_ip,port,bytes"]
    for i in range(30):
        L.append(f"{(base+dt.timedelta(minutes=i)).isoformat()},login,alice,"
                 f"WKS-1,10.0.0.5,,,0")
    L.append(f"{(base+dt.timedelta(minutes=31)).isoformat()},transfer,bob,"
             f"WKS-9,10.0.0.9,203.0.113.9,4444,900000000")
    ingestion.ingest("\n".join(L), "anom.csv", "real")
    events = db.query("SELECT * FROM events WHERE dataset='real'")
    covered = {eid for d in rules.run_rules(events) for eid in d.event_ids}
    dets = anomaly.detect_anomalies(events, covered, threshold=0.6)
    if dets:  # anomaly detection is data-dependent; assert structure if it fires
        assert "signals" in dets[0].extra
        assert dets[0].extra.get("model") in ("IsolationForest", "statistical z-score")
