"""Agent consensus.

Each agent expresses a stance on whether a genuine, actionable threat exists.
We convert every assessment into a 0..1 "threat belief", then measure both the
central tendency (consensus score) and the dispersion (agreement). Significant
disagreement suppresses automation and routes to human review.
"""
from __future__ import annotations

import statistics

# verdict phrases that mean "this agent does NOT think there's a threat"
NEGATIVE_MARKERS = (
    "no confirmed", "no historical", "insufficient", "weak", "isolated",
    "low risk", "not ", "no malicious", "benign", "clean",
)


def _stance(assessment: dict) -> float:
    verdict = (assessment.get("verdict") or "").lower()
    conf = float(assessment.get("confidence") or 0.0)
    negative = any(m in verdict for m in NEGATIVE_MARKERS)
    # If the agent is confident about a NEGATIVE verdict, its threat-belief is low.
    return round(1.0 - conf, 3) if negative else round(conf, 3)


def compute(assessments: list[dict]) -> dict:
    stances = {a["agent"]: _stance(a) for a in assessments}
    vals = list(stances.values())
    if not vals:
        return {"score": 0.0, "agreement": 0.0, "mean_confidence": 0.0,
                "disagreement": True, "stances": {}}
    mean_belief = statistics.fmean(vals)
    spread = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    agreement = round(max(0.0, 1.0 - 2.0 * spread), 3)
    mean_conf = round(statistics.fmean(
        [float(a.get("confidence") or 0) for a in assessments]), 3)
    # Consensus score blends how strongly agents believe in a threat with how
    # much they agree.
    score = round(mean_belief * (0.6 + 0.4 * agreement), 3)
    return {
        "score": score,
        "agreement": agreement,
        "mean_belief": round(mean_belief, 3),
        "mean_confidence": mean_conf,
        "spread": round(spread, 3),
        "disagreement": agreement < 0.5,
        "stances": stances,
    }
