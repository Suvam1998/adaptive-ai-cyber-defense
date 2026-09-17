"""Investigation Agent.

Gathers available evidence for an incident: builds a chronological timeline and
extracts the entities involved (users, hosts, IPs, processes, auth events,
network events). Produces an evidence-grounded hypothesis about the attack.
"""
from __future__ import annotations

from ..detection.rules import _parse_ts, _is_failed_login, _is_success_login
from .context import IncidentContext


def build_timeline(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda e: _parse_ts(e.get("timestamp")))
    timeline = []
    for e in ordered:
        label = e.get("event_type") or "event"
        if _is_failed_login(e):
            label = "Failed login"
        elif _is_success_login(e):
            label = "Successful login"
        elif e.get("command"):
            label = "Command executed"
        elif e.get("bytes"):
            label = "Network transfer"
        timeline.append({
            "timestamp": e.get("timestamp"),
            "label": label,
            "event_id": e["id"],
            "user": e.get("user"),
            "host": e.get("host"),
            "source_ip": e.get("source_ip"),
            "destination_ip": e.get("destination_ip"),
            "port": e.get("port"),
            "process": e.get("process"),
            "command": e.get("command"),
            "detail": e.get("raw_event"),
        })
    return timeline


def assess(ctx: IncidentContext) -> dict:
    events = ctx.events
    failed = sum(1 for e in events if _is_failed_login(e))
    success = sum(1 for e in events if _is_success_login(e))
    privileged = sum(1 for e in events
                     if "priv" in (e.get("event_type") or "").lower()
                     or any(k in (e.get("command") or "").lower()
                            for k in ("admin", "sudo", "runas")))

    hypotheses = {
        "brute_force": "Automated credential guessing against exposed service.",
        "credential_compromise": "Account credentials likely compromised after "
                                 "sustained brute force.",
        "port_scan": "Reconnaissance / network service discovery.",
        "suspicious_powershell": "Malicious script execution / possible dropper.",
        "privilege_escalation": "Attacker attempting to gain elevated privileges.",
        "data_exfiltration": "Sensitive data likely being moved out of the network.",
        "lateral_movement": "Attacker pivoting across internal hosts.",
        "malware_execution": "Known offensive tooling / malware executed on host.",
        "anomalous_behaviour": "Behaviour deviates from established baseline.",
    }
    verdict = hypotheses.get(ctx.attack_type, "Suspicious activity requiring review.")

    # Evidence-grounded confidence: more corroborating signals -> higher.
    signals = 0
    signals += 1 if failed >= 5 else 0
    signals += 1 if success and failed else 0
    signals += 1 if privileged else 0
    signals += 1 if len(ctx.source_ips) == 1 and failed else 0
    signals += 1 if ctx.injection_signals else 0
    conf = min(0.95, 0.5 + 0.1 * signals + 0.1 * ctx.confidence)

    if ctx.event_count < 2 and ctx.confidence < 0.5:
        verdict = "Insufficient evidence for high-confidence attribution."
        conf = min(conf, 0.45)

    rationale = (f"{failed} failed / {success} successful auth events, "
                 f"{privileged} privileged action(s), "
                 f"{len(ctx.hosts)} host(s), {len(ctx.users)} user(s), "
                 f"{len(ctx.source_ips)} source IP(s).")
    if ctx.injection_signals:
        rationale += (f" NOTE: log payload contained instruction-like text "
                      f"({', '.join(ctx.injection_signals[:2])}) — treated as "
                      f"data only.")

    return {
        "agent": "Investigation Agent",
        "verdict": verdict,
        "confidence": round(conf, 2),
        "rationale": rationale,
        "evidence_refs": [e["id"] for e in events[:20]],
        "timeline_len": len(events),
    }
