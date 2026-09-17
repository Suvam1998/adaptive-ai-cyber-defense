"""Anomaly detection.

Primary model: scikit-learn IsolationForest over lightweight per-event
features. For very small datasets (where an ML model is meaningless) we fall
back to transparent statistical thresholding. Both paths return an
*explanation* of why an event/entity looked anomalous — the system must always
justify a flag.
"""
from __future__ import annotations

import datetime as _dt
import math
from collections import defaultdict

import numpy as np

from ..config import config
from .rules import Detection, _parse_ts, _is_failed_login, _is_success_login

FEATURES = ["hour", "port", "log_bytes", "is_failed", "is_success",
            "ip_rarity", "type_rarity"]


def _build_features(events: list[dict]):
    ip_counts: dict = defaultdict(int)
    type_counts: dict = defaultdict(int)
    for e in events:
        ip_counts[e.get("source_ip")] += 1
        type_counts[(e.get("event_type") or "unknown").lower()] += 1

    rows, ids = [], []
    for e in events:
        ts = _parse_ts(e.get("timestamp"))
        hour = ts.hour if ts != _dt.datetime.min else 12
        port = e.get("port") or 0
        b = e.get("bytes") or 0
        log_bytes = math.log10(b + 1)
        is_failed = 1.0 if _is_failed_login(e) else 0.0
        is_success = 1.0 if _is_success_login(e) else 0.0
        ip_rarity = 1.0 / ip_counts[e.get("source_ip")]
        type_rarity = 1.0 / type_counts[(e.get("event_type") or "unknown").lower()]
        rows.append([hour, port, log_bytes, is_failed, is_success,
                     ip_rarity, type_rarity])
        ids.append(e["id"])
    return np.array(rows, dtype=float), ids


def _explain(feature_row: np.ndarray, means: np.ndarray,
             stds: np.ndarray) -> str:
    """Explain which features were most unusual for this event."""
    labels = {
        "hour": "off-hours activity",
        "port": "unusual destination port",
        "log_bytes": "unusually large data volume",
        "is_failed": "authentication failure pattern",
        "is_success": "authentication success pattern",
        "ip_rarity": "rarely-seen source IP",
        "type_rarity": "rare event type",
    }
    with np.errstate(divide="ignore", invalid="ignore"):
        z = np.abs((feature_row - means) / np.where(stds == 0, 1, stds))
    top = np.argsort(z)[::-1][:2]
    reasons = [labels[FEATURES[i]] for i in top if z[i] > 1.0]
    return ", ".join(reasons) if reasons else "multivariate outlier"


def _signal_list(feature_row: np.ndarray, means: np.ndarray,
                 stds: np.ndarray) -> list[str]:
    """All behavioural signals whose value is unusual (|z| > 1). These are
    EXPLANATORY HEURISTICS derived from the features — NOT the model's internal
    reasoning. The model score is reported separately."""
    labels = {
        "hour": "off-hours activity",
        "port": "unusual destination port",
        "log_bytes": "unusually large data volume",
        "is_failed": "authentication failure pattern",
        "is_success": "authentication success pattern",
        "ip_rarity": "rarely-seen source IP",
        "type_rarity": "rare event type",
    }
    with np.errstate(divide="ignore", invalid="ignore"):
        z = np.abs((feature_row - means) / np.where(stds == 0, 1, stds))
    order = np.argsort(z)[::-1]
    return [labels[FEATURES[i]] for i in order if z[i] > 1.0]


def score_events(events: list[dict]) -> dict[int, float]:
    """Return {event_id: anomaly_score in 0..1} (higher = more anomalous)."""
    if len(events) < 8:
        return _statistical_scores(events)
    X, ids = _build_features(events)
    try:
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(
            n_estimators=120,
            contamination=min(0.4, max(0.02, config.ANOMALY_CONTAMINATION)),
            random_state=42,
        )
        model.fit(X)
        raw = -model.score_samples(X)  # higher = more anomalous
        lo, hi = raw.min(), raw.max()
        norm = (raw - lo) / (hi - lo) if hi > lo else np.zeros_like(raw)
        return {ids[i]: round(float(norm[i]), 3) for i in range(len(ids))}
    except Exception:
        return _statistical_scores(events)


def _statistical_scores(events: list[dict]) -> dict[int, float]:
    """Transparent fallback: z-score on bytes + failed-login weighting."""
    if not events:
        return {}
    byte_vals = np.array([float(e.get("bytes") or 0) for e in events])
    mean, std = byte_vals.mean(), byte_vals.std() or 1.0
    scores = {}
    for e, b in zip(events, byte_vals):
        z = abs((b - mean) / std)
        s = min(1.0, z / 4.0)
        if _is_failed_login(e):
            s = max(s, 0.4)
        scores[e["id"]] = round(float(s), 3)
    return scores


def detect_anomalies(events: list[dict], covered_ids: set[int],
                     threshold: float = 0.75) -> list[Detection]:
    """Produce anomaly-based detections for high-scoring events NOT already
    explained by a rule."""
    scores = score_events(events)
    if not scores:
        return []
    X, ids = _build_features(events) if len(events) >= 8 else (None, [])
    means = X.mean(axis=0) if X is not None and len(X) else None
    stds = X.std(axis=0) if X is not None and len(X) else None
    id_to_row = {ids[i]: X[i] for i in range(len(ids))} if X is not None else {}
    by_id = {e["id"]: e for e in events}

    detections = []
    for eid, score in scores.items():
        if score < threshold or eid in covered_ids:
            continue
        e = by_id[eid]
        model = "IsolationForest" if len(events) >= 8 else "statistical z-score"
        if means is not None and eid in id_to_row:
            signals = _signal_list(id_to_row[eid], means, stds)
        else:
            signals = ["large data volume / failed-auth weighting"]
        why = ", ".join(signals) if signals else "multivariate outlier"
        det = Detection(
            attack_type="anomalous_behaviour",
            severity="High" if score >= 0.9 else "Medium",
            confidence=round(min(0.9, score), 2),
            reason=(f"Behavioural anomaly (model score {score:.2f}, {model}); "
                    f"observed signals: {why}."),
            event_ids=[eid],
            source_ips={e.get("source_ip")} if e.get("source_ip") else set(),
            users={e.get("user")} if e.get("user") else set(),
            hosts={e.get("host")} if e.get("host") else set(),
            destination_ips={e.get("destination_ip")} if e.get("destination_ip") else set(),
            detector="anomaly",
            anomaly_score=score,
            correlation_key=f"anomaly:{e.get('source_ip') or e.get('host') or eid}",
            extra={"model": model, "model_score": score, "signals": signals},
        )
        detections.append(det)
    return detections
