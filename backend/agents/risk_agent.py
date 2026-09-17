"""Risk Assessment Agent — explainable risk scoring.

Risk is a weighted sum of five documented components, each capped at a maximum
so the total is out of 100. The formula is intentionally transparent so every
score can be broken down and justified to an analyst.

    Component              Max   Driven by
    ---------------------  ----  --------------------------------------------
    Evidence confidence     30   detection + agent confidence, evidence count
    Asset criticality       25   sensitivity & count of affected hosts/users
    Threat severity         20   detection severity (Critical/High/Med/Low)
    Behaviour anomaly       15   ML/statistical anomaly score
    Threat intelligence     10   local CTI reputation of involved indicators

The 0..1 ``risk_score`` used elsewhere is total/100.
"""
from __future__ import annotations

from .context import IncidentContext

MAX = {"evidence": 30, "asset": 25, "severity": 20, "anomaly": 15, "intel": 10}

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3}

# crude asset-criticality heuristics for a demo (documented in docs/architecture)
CRITICAL_HOST_MARKERS = ("dc", "domain", "prod", "db", "sql", "finance",
                         "payroll", "vault", "admin", "core")
CRITICAL_USER_MARKERS = ("admin", "root", "svc", "service", "backup", "domain")


def _asset_criticality(ctx: IncidentContext) -> tuple[float, str]:
    hosts = [h for h in ctx.hosts if h]
    users = [u for u in ctx.users if u]
    crit = 0.4  # baseline
    notes = []
    for h in hosts:
        if any(m in h.lower() for m in CRITICAL_HOST_MARKERS):
            crit = max(crit, 0.9)
            notes.append(f"critical host {h}")
            break
    for u in users:
        if any(m in u.lower() for m in CRITICAL_USER_MARKERS):
            crit = max(crit, 0.85)
            notes.append(f"privileged user {u}")
            break
    # more affected assets -> more risk
    spread = min(0.2, 0.05 * (len(hosts) + len(users)))
    crit = min(1.0, crit + spread)
    return crit, ("; ".join(notes) if notes else "standard assets")


def compute(ctx: IncidentContext, agent_confidence: float,
            ti_assessment: dict) -> dict:
    # evidence confidence component
    ev_ratio = min(1.0, 0.4 * ctx.confidence + 0.4 * agent_confidence
                   + 0.2 * min(1.0, ctx.event_count / 10.0))
    evidence = ev_ratio * MAX["evidence"]

    # asset criticality
    asset_ratio, asset_note = _asset_criticality(ctx)
    asset = asset_ratio * MAX["asset"]

    # severity
    sev_ratio = SEVERITY_WEIGHT.get((ctx.severity or "medium").lower(), 0.55)
    severity = sev_ratio * MAX["severity"]

    # anomaly
    anomaly = min(1.0, ctx.anomaly_score) * MAX["anomaly"]

    # threat intel
    ti_score = 0
    if ti_assessment.get("matches"):
        ti_score = max(m["score"] for m in ti_assessment["matches"])
    intel = (ti_score / 100.0) * MAX["intel"]

    breakdown = {
        "evidence_confidence": {"score": round(evidence, 1), "max": MAX["evidence"],
                                "note": f"detection+agent confidence, "
                                        f"{ctx.event_count} events"},
        "asset_criticality": {"score": round(asset, 1), "max": MAX["asset"],
                              "note": asset_note},
        "threat_severity": {"score": round(severity, 1), "max": MAX["severity"],
                            "note": f"severity={ctx.severity}"},
        "behaviour_anomaly": {"score": round(anomaly, 1), "max": MAX["anomaly"],
                             "note": f"anomaly score {ctx.anomaly_score:.2f}"},
        "threat_intelligence": {"score": round(intel, 1), "max": MAX["intel"],
                               "note": (f"CTI reputation {ti_score}"
                                        if ti_score else "no CTI hit")},
    }
    total = sum(c["score"] for c in breakdown.values())
    total = round(min(100.0, total), 1)
    return {
        "total": total,
        "risk_score": round(total / 100.0, 3),
        "breakdown": breakdown,
    }


def assess(ctx: IncidentContext, agent_confidence: float,
           ti_assessment: dict) -> dict:
    risk = compute(ctx, agent_confidence, ti_assessment)
    total = risk["total"]
    if total >= 80:
        verdict, band = "Critical risk", "critical"
    elif total >= 65:
        verdict, band = "High risk", "high"
    elif total >= 40:
        verdict, band = "Medium risk", "medium"
    else:
        verdict, band = "Low risk", "low"
    return {
        "agent": "Risk Assessment Agent",
        "verdict": verdict,
        "confidence": round(min(0.97, 0.5 + total / 200.0 + agent_confidence / 4), 2),
        "rationale": (f"Composite risk {total}/100 ({band}). "
                      + "; ".join(f"{k.replace('_', ' ')} "
                                  f"{v['score']}/{v['max']}"
                                  for k, v in risk["breakdown"].items())),
        "evidence_refs": [],
        "risk": risk,
        "band": band,
    }
