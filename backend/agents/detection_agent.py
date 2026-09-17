"""Detection Agent.

Summarises what the detection layer fired and how strong it looks. It does not
re-run detection; it interprets the detection evidence already attached to the
incident and states, with confidence, whether a genuine threat is present.
"""
from __future__ import annotations

from .context import IncidentContext


def assess(ctx: IncidentContext) -> dict:
    n = ctx.event_count
    conf = ctx.confidence
    if ctx.anomaly_score:
        conf = max(conf, 0.5 * conf + 0.5 * ctx.anomaly_score)

    if conf >= 0.75 and n >= 3:
        verdict = "Threat confirmed by detection signals"
    elif conf >= 0.55:
        verdict = "Threat likely"
    else:
        verdict = "Weak / low-confidence signal"

    rationale = (f"{ctx.attack_type.replace('_', ' ')} pattern across {n} "
                 f"correlated event(s). {ctx.detection_reason}")
    if ctx.anomaly_score:
        rationale += f" Anomaly score {ctx.anomaly_score:.2f}."

    return {
        "agent": "Detection Agent",
        "verdict": verdict,
        "confidence": round(min(0.98, conf), 2),
        "rationale": rationale,
        "evidence_refs": [e["id"] for e in ctx.events[:20]],
    }
