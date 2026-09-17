"""Analytics aggregation for the dashboard and analytics pages.

All queries are scoped by ``dataset`` so real and demo metrics never mix.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from . import database as db


def dashboard(dataset: str = "real") -> dict:
    incs = db.query("SELECT * FROM incidents WHERE dataset=?", (dataset,))
    by_sev = Counter((i["severity"] or "Medium") for i in incs)
    active = [i for i in incs if i["status"] not in ("Closed", "Contained")]
    investigating = [i for i in incs if i["status"] == "Investigating"]

    resp_rows = db.query(
        "SELECT r.* FROM responses r JOIN incidents i "
        "ON r.incident_id=i.incident_id WHERE i.dataset=?", (dataset,))
    executed = [r for r in resp_rows if r["status"] == "executed"]
    escalations = [i for i in incs if i["status"] == "Awaiting Approval"]

    outcomes = db.query(
        "SELECT o.* FROM response_outcomes o JOIN incidents i "
        "ON o.incident_id=i.incident_id WHERE i.dataset=?", (dataset,))
    success = [o for o in outcomes if o["outcome"] == "SUCCESS"]
    success_rate = round(100 * len(success) / len(outcomes), 1) if outcomes else None

    # false positive proxy: incidents closed with THREAT_PERSISTS never, but
    # low-risk incidents auto-closed with no action -> not measured reliably.
    fp = [i for i in incs if (i["risk_score"] or 0) < 0.35
          and i["status"] in ("Closed", "Contained")]
    fp_rate = round(100 * len(fp) / len(incs), 1) if incs else None

    investigated = [i for i in incs if i["status"] != "New"]
    avg_risk = (round(100 * sum((i["risk_score"] or 0) for i in incs) / len(incs), 1)
                if incs else None)
    avg_conf = (round(100 * sum((i["confidence"] or 0) for i in investigated)
                      / len(investigated), 1) if investigated else None)
    autonomous = [r for r in executed if r["requires_approval"] == 0]
    autonomous_rate = (round(100 * len(autonomous) / len(executed), 1)
                       if executed else None)
    escalation_rate = (round(100 * len(escalations) / len(incs), 1)
                       if incs else None)

    # memory reuse: incidents whose attack_type has a TRUSTED learned experience
    trusted_types = {m["attack_type"] for m in db.query(
        "SELECT DISTINCT attack_type FROM memory WHERE validation_status='trusted'")}
    reused = [i for i in incs if i["attack_type"] in trusted_types]
    memory_reuse_rate = (round(100 * len(reused) / len(incs), 1) if incs else None)

    # detection method distribution (measured from incidents.detection_method)
    method_dist = Counter((i["detection_method"] or "rule") for i in incs)

    return {
        "dataset": dataset,
        "active_incidents": len(active),
        "by_severity": {s: by_sev.get(s, 0)
                        for s in ("Critical", "High", "Medium", "Low")},
        "threats_detected": len(incs),
        "investigations_running": len(investigating),
        "automated_responses": len(autonomous),
        "responses_executed": len(executed),
        "human_escalations": len(escalations),
        "response_success_rate": success_rate,
        "avg_investigation_time_s": _avg_investigation_time(incs),
        "avg_response_time_s": _avg_response_time(resp_rows, outcomes),
        "avg_risk": avg_risk,
        "avg_confidence": avg_conf,
        "autonomous_decision_rate": autonomous_rate,
        "human_escalation_rate": escalation_rate,
        "memory_reuse_rate": memory_reuse_rate,
        "strategy_success_rate": success_rate,
        "detection_method_distribution": dict(method_dist),
        "false_positive_rate": fp_rate,
        "total_events": db.scalar(
            "SELECT COUNT(*) FROM events WHERE dataset=?", (dataset,)) or 0,
        # Honesty labels: which metrics are measured vs estimated vs simulated.
        "metric_types": {
            "measured": ["threats_detected", "active_incidents",
                         "responses_executed", "human_escalations",
                         "response_success_rate", "autonomous_decision_rate",
                         "human_escalation_rate", "detection_method_distribution",
                         "strategy_success_rate", "total_events"],
            "estimated": ["avg_risk", "avg_confidence", "memory_reuse_rate",
                          "false_positive_rate", "avg_investigation_time_s",
                          "avg_response_time_s"],
            "simulated": ["responses_executed"],
        },
    }


def _avg_investigation_time(incs: list[dict]):
    # created_at -> updated_at for investigated incidents (seconds), demo-scale.
    import datetime as _dt
    spans = []
    for i in incs:
        if i["status"] in ("New",):
            continue
        try:
            c = _dt.datetime.fromisoformat(i["created_at"])
            u = _dt.datetime.fromisoformat(i["updated_at"])
            spans.append(max(0.0, (u - c).total_seconds()))
        except (ValueError, TypeError):
            continue
    return round(sum(spans) / len(spans), 1) if spans else None


def _avg_response_time(resps: list[dict], outcomes: list[dict]):
    import datetime as _dt
    by_id = {r["response_id"]: r for r in resps}
    spans = []
    for o in outcomes:
        r = by_id.get(o["response_id"])
        if not r:
            continue
        try:
            c = _dt.datetime.fromisoformat(r["created_at"])
            u = _dt.datetime.fromisoformat(o["created_at"])
            spans.append(max(0.0, (u - c).total_seconds()))
        except (ValueError, TypeError):
            continue
    return round(sum(spans) / len(spans), 1) if spans else None


def charts(dataset: str = "real") -> dict:
    incs = db.query("SELECT * FROM incidents WHERE dataset=?", (dataset,))

    # threats over time (by hour bucket)
    time_buckets = defaultdict(int)
    for i in incs:
        ts = (i["created_at"] or "")[:13]  # YYYY-MM-DDTHH
        time_buckets[ts] += 1
    threats_over_time = [{"t": k, "count": v}
                         for k, v in sorted(time_buckets.items())]

    by_severity = Counter(i["severity"] or "Medium" for i in incs)
    by_attack = Counter(i["attack_type"] or "unknown" for i in incs)
    by_method = Counter((i["detection_method"] or "rule") for i in incs)

    # attack techniques
    tech = Counter()
    for i in incs:
        for t in db.jload(i["mitre"], []) or []:
            tech[f"{t['id']} {t['name']}"] += 1

    outcomes = db.query(
        "SELECT o.outcome, COUNT(*) c FROM response_outcomes o "
        "JOIN incidents i ON o.incident_id=i.incident_id "
        "WHERE i.dataset=? GROUP BY o.outcome", (dataset,))
    outcome_dist = {o["outcome"]: o["c"] for o in outcomes}

    # risk distribution buckets
    risk_bins = {"0-20": 0, "20-40": 0, "40-60": 0, "60-80": 0, "80-100": 0}
    for i in incs:
        r = (i["risk_score"] or 0) * 100
        if r < 20:
            risk_bins["0-20"] += 1
        elif r < 40:
            risk_bins["20-40"] += 1
        elif r < 60:
            risk_bins["40-60"] += 1
        elif r < 80:
            risk_bins["60-80"] += 1
        else:
            risk_bins["80-100"] += 1

    # top source IPs / hosts / user risk
    ip_counter = Counter()
    host_counter = Counter()
    user_risk = defaultdict(float)
    for i in incs:
        for ip in db.jload(i["source_ips"], []) or []:
            ip_counter[ip] += 1
        for h in db.jload(i["affected_hosts"], []) or []:
            host_counter[h] += 1
        for u in db.jload(i["affected_users"], []) or []:
            user_risk[u] = max(user_risk[u], (i["risk_score"] or 0) * 100)

    return {
        "dataset": dataset,
        "threats_over_time": threats_over_time,
        "by_severity": dict(by_severity),
        "by_attack_type": dict(by_attack),
        "detection_methods": dict(by_method),
        "attack_techniques": dict(tech.most_common(10)),
        "response_outcomes": outcome_dist,
        "risk_distribution": risk_bins,
        "top_source_ips": ip_counter.most_common(8),
        "top_hosts": host_counter.most_common(8),
        "user_risk": sorted(user_risk.items(), key=lambda kv: -kv[1])[:8],
    }
