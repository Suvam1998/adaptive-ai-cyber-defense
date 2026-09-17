"""Controlled, reproducible evaluation against labelled real datasets.

Computes detection quality metrics (precision, recall, F1, false-positive rate)
by comparing the SOC's detections against the **ground-truth `label`** column of
a labelled dataset (e.g. CIC-IDS2017 / CSE-CIC-IDS2018). It also measures the
baseline (rule-only detection) against the proposed pipeline (rules + anomaly +
multi-agent), and records real measured timings.

Honesty rules:
* If no labelled data is present, every metric is reported as "Not available"
  — no numbers are invented.
* Ground truth comes only from the dataset's own labels; predictions come only
  from what the SOC actually detected.
"""
from __future__ import annotations

import time

from . import database as db
from .detection import anomaly, rules

# label values that mean "not an attack"
BENIGN_LABELS = {"benign", "normal", "background", "0", "none", ""}

NA = "Not available"


def _is_attack_label(label) -> bool:
    return bool(label) and str(label).strip().lower() not in BENIGN_LABELS


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) else None)
    fpr = fp / (fp + tn) if (fp + tn) else None
    acc = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else None
    r = lambda x: round(x, 4) if x is not None else NA
    return {
        "true_positives": tp, "false_positives": fp,
        "true_negatives": tn, "false_negatives": fn,
        "precision": r(precision), "recall": r(recall), "f1": r(f1),
        "false_positive_rate": r(fpr), "accuracy": r(acc),
    }


def _confusion(events: list[dict], flagged_ids: set[int]) -> dict:
    tp = fp = tn = fn = 0
    for e in events:
        attack = _is_attack_label(e.get("label"))
        flagged = e["id"] in flagged_ids
        if attack and flagged:
            tp += 1
        elif attack and not flagged:
            fn += 1
        elif not attack and flagged:
            fp += 1
        else:
            tn += 1
    return _metrics(tp, fp, tn, fn)


def evaluate(dataset: str = "real") -> dict:
    """Evaluate detection quality on labelled data in ``dataset``."""
    events = db.query("SELECT * FROM events WHERE dataset=?", (dataset,))
    labelled = [e for e in events if e.get("label") not in (None, "")]

    result = {
        "dataset": dataset,
        "records_total": len(events),
        "records_labelled": len(labelled),
        "labelled_available": bool(labelled),
        "attack_types": {},
        "baseline": None,
        "proposed": None,
        "timings": {},
        "notes": [],
    }

    if not labelled:
        result["notes"].append(
            "No labelled dataset loaded. Load a CIC-IDS / CSE-CIC-IDS CSV (with a "
            "Label column) to compute precision/recall/F1. Metrics: " + NA + ".")
        result["proposed"] = {k: NA for k in
                              ("precision", "recall", "f1",
                               "false_positive_rate", "accuracy")}
        result["baseline"] = dict(result["proposed"])
        return result

    # attack-type distribution from ground-truth labels
    dist: dict[str, int] = {}
    for e in labelled:
        lab = str(e.get("label")).strip()
        dist[lab] = dist.get(lab, 0) + 1
    result["attack_types"] = dict(sorted(dist.items(), key=lambda kv: -kv[1]))

    # --- proposed pipeline: events actually incorporated into incidents ---
    proposed_flagged = {
        r["event_ref"] for r in db.query(
            "SELECT DISTINCT e.event_ref FROM evidence e "
            "JOIN incidents i ON e.incident_id=i.incident_id "
            "WHERE i.dataset=? AND e.kind='event' AND e.event_ref IS NOT NULL",
            (dataset,))
    }
    result["proposed"] = _confusion(labelled, proposed_flagged)

    # --- baseline: rule-only detection over the same labelled events ---
    t0 = time.perf_counter()
    rule_dets = rules.run_rules(labelled)
    rule_ms = (time.perf_counter() - t0) * 1000.0
    baseline_flagged = {eid for d in rule_dets for eid in d.event_ids}
    result["baseline"] = _confusion(labelled, baseline_flagged)

    # --- measured timings (real) ---
    t1 = time.perf_counter()
    covered = set(baseline_flagged)
    anomaly.detect_anomalies(labelled, covered)
    anomaly_ms = (time.perf_counter() - t1) * 1000.0
    result["timings"] = {
        "rule_detection_ms": round(rule_ms, 2),
        "anomaly_detection_ms": round(anomaly_ms, 2),
        "detection_latency_ms_per_event":
            round((rule_ms + anomaly_ms) / max(1, len(labelled)), 4),
        "investigation_time_s": _avg_investigation_time(dataset),
        "response_recommendation_time_s": NA,  # measured per-incident elsewhere
    }
    result["notes"].append(
        "Ground truth is the dataset's own Label column; predictions are the "
        "events the SOC actually incorporated into incidents. Flow datasets lack "
        "auth/process context, so recall is bounded by what flow features expose.")
    return result


def _avg_investigation_time(dataset: str):
    from . import analytics
    v = analytics.dashboard(dataset).get("avg_investigation_time_s")
    return v if v is not None else NA
