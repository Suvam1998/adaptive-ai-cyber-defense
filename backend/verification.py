"""Attack-specific response verification.

Verification measures whether the threat indicators for an incident would
persist *after* a (simulated) response. Crucially it does this **without ever
mutating the original events** — the response effect is modelled as a coverage
*predicate* (e.g. "block source IP 203.0.113.66" neutralises events from that
IP), and verification simply recomputes indicators over the event set with the
covered events filtered out.

The indicator definition depends on the detected attack type, so verification
for a port scan is different from verification for data exfiltration.

Public API::

    verify_response(incident, response_action, target,
                    before_events, after_events=None) -> dict
"""
from __future__ import annotations

from .detection.rules import _is_failed_login, _is_success_login

# --------------------------------------------------------------------------- #
# Attack-type indicator extractors
# --------------------------------------------------------------------------- #
# Each extractor takes the incident's events and returns
#   (indicator_dict, contributing_event_ids)
# indicator_dict is a small map of named indicators -> count.


def _blob(e: dict) -> str:
    return f"{e.get('process') or ''} {e.get('command') or ''}".lower()


def _ind_brute_force(events):
    ids = [e["id"] for e in events if _is_failed_login(e)]
    return {"auth_failures": len(ids)}, ids


def _ind_credential_compromise(events):
    fails = [e for e in events if _is_failed_login(e)]
    succ = [e for e in events if _is_success_login(e)]
    priv = [e for e in events if "priv" in (e.get("event_type") or "").lower()
            or any(k in _blob(e) for k in ("whoami /priv", "admin", "runas", "sudo"))]
    ids = [e["id"] for e in fails + succ + priv]
    return ({"auth_failures": len(fails), "successful_logins": len(succ),
             "privileged_activity": len(priv)}, ids)


def _ind_port_scan(events):
    conn = [e for e in events if e.get("port") is not None
            or "connection" in (e.get("event_type") or "").lower()
            or "scan" in (e.get("event_type") or "").lower()]
    ports = {e.get("port") for e in conn if e.get("port") is not None}
    return ({"scan_connections": len(conn), "distinct_ports": len(ports)},
            [e["id"] for e in conn])


def _ind_malware(events):
    hits = [e for e in events if "malware" in (e.get("event_type") or "").lower()
            or any(m in (e.get("process") or "").lower()
                   for m in ("mimikatz", "psexec", "cobaltstrike", "nc.exe",
                             "ncat", "wce.exe"))]
    return {"malware_indicators": len(hits)}, [e["id"] for e in hits]


def _ind_powershell(events):
    hits = [e for e in events if "powershell" in _blob(e) or "pwsh" in _blob(e)
            or any(m in _blob(e) for m in ("-enc", "downloadstring", "iex",
                                           "-nop", "hidden", "bypass"))]
    return {"suspicious_process_exec": len(hits)}, [e["id"] for e in hits]


def _ind_privilege_escalation(events):
    hits = [e for e in events if "priv" in (e.get("event_type") or "").lower()
            or "escalat" in (e.get("event_type") or "").lower()
            or any(k in _blob(e) for k in ("whoami /priv", "net localgroup",
                                           "runas", "getsystem", "sedebug"))]
    return {"privileged_activity": len(hits)}, [e["id"] for e in hits]


def _ind_lateral_movement(events):
    hits = [e for e in events
            if "remote" in (e.get("event_type") or "").lower()
            or "lateral" in (e.get("event_type") or "").lower()
            or "rdp" in (e.get("event_type") or "").lower()
            or (_is_success_login(e) and e.get("user"))]
    hosts = {e.get("host") for e in hits if e.get("host")}
    return ({"remote_auth_events": len(hits), "distinct_hosts": len(hosts)},
            [e["id"] for e in hits])


def _ind_data_exfiltration(events):
    hits = [e for e in events
            if "exfil" in (e.get("event_type") or "").lower()
            or (e.get("bytes") or 0) > 0 and e.get("destination_ip")]
    total_bytes = sum(int(e.get("bytes") or 0) for e in hits)
    return ({"outbound_transfers": len(hits), "outbound_bytes": total_bytes},
            [e["id"] for e in hits])


def _ind_anomalous(events):
    # generic: any event tied to the incident is a behavioural indicator
    ids = [e["id"] for e in events]
    return {"anomalous_events": len(ids)}, ids


EXTRACTORS = {
    "brute_force": _ind_brute_force,
    "credential_compromise": _ind_credential_compromise,
    "port_scan": _ind_port_scan,
    "malware_execution": _ind_malware,
    "suspicious_powershell": _ind_powershell,
    "privilege_escalation": _ind_privilege_escalation,
    "lateral_movement": _ind_lateral_movement,
    "data_exfiltration": _ind_data_exfiltration,
    "anomalous_behaviour": _ind_anomalous,
}

VERIFICATION_METHOD = {
    "brute_force": "Re-count authentication failures from the source after the "
                   "response.",
    "credential_compromise": "Re-check suspicious auth, source IP activity and "
                             "privileged actions for the account.",
    "port_scan": "Re-check scanning / connection attempts from the source.",
    "malware_execution": "Re-check malware / offensive-tool process indicators on "
                         "the host.",
    "suspicious_powershell": "Re-check suspicious PowerShell / process execution.",
    "privilege_escalation": "Re-check continued privileged activity.",
    "lateral_movement": "Re-check remote authentication / connections by the user.",
    "data_exfiltration": "Re-check outbound connections and unusual outbound bytes.",
    "anomalous_behaviour": "Re-check whether the anomalous behaviour persists.",
}


# --------------------------------------------------------------------------- #
# Response coverage predicate (models the simulated effect, no mutation)
# --------------------------------------------------------------------------- #
def action_covers(event: dict, action: str, target: str) -> bool:
    """Would this response action neutralise this event? (pure predicate).

    This is how the simulated effect is applied during verification: we do not
    edit the event, we simply decide whether the action would have stopped it.
    """
    if not action:
        return False
    a = action.lower()
    if any(k in a for k in ("collect", "monitor", "evidence")):
        return False  # non-intrusive actions neutralise nothing
    if not target or target in ("incident scope", "unknown", "none"):
        return False
    if "destination" in a or "domain" in a:
        return event.get("destination_ip") == target
    if "block" in a and ("ip" in a or "source" in a):
        return event.get("source_ip") == target
    if "isolate" in a:  # isolate host/endpoint
        return event.get("host") == target
    if any(k in a for k in ("disable", "account", "revoke", "reset", "session")):
        return event.get("user") == target
    if any(k in a for k in ("terminate", "kill", "process")):
        return (event.get("process") or "").lower() == str(target).lower()
    # generic block: match any entity equal to the target
    return target in (event.get("source_ip"), event.get("destination_ip"),
                      event.get("user"), event.get("host"))


def _coverage_dimension(action: str) -> str:
    a = (action or "").lower()
    if "destination" in a or "domain" in a:
        return "destination_ip"
    if "isolate" in a:
        return "host"
    if any(k in a for k in ("disable", "account", "revoke", "reset", "session")):
        return "user"
    if any(k in a for k in ("terminate", "kill", "process")):
        return "process"
    if "block" in a:
        return "source_ip"
    return "none"


def apply_effect(before_events: list[dict], action: str,
                 target: str) -> tuple[list[dict], list[int]]:
    """Return (surviving_events, neutralised_event_ids) after the simulated
    effect — WITHOUT modifying any event."""
    surviving, neutralised = [], []
    for e in before_events:
        if action_covers(e, action, target):
            neutralised.append(e["id"])
        else:
            surviving.append(e)
    return surviving, neutralised


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def verify_response(incident: dict, response_action: str, target: str,
                    before_events: list[dict],
                    after_events: list[dict] | None = None) -> dict:
    """Attack-specific verification.

    If ``after_events`` is not supplied, the "after" state is derived by applying
    the response coverage predicate to ``before_events`` (the simulated effect).
    """
    attack_type = incident.get("attack_type") or "anomalous_behaviour"
    extractor = EXTRACTORS.get(attack_type, _ind_anomalous)

    ind_before, before_ids = extractor(before_events)
    if after_events is None:
        after_events, neutralised = apply_effect(before_events, response_action,
                                                 target)
    else:
        neutralised = [e["id"] for e in before_events
                       if e["id"] not in {a["id"] for a in after_events}]
    ind_after, after_ids = extractor(after_events)

    total_before = sum(ind_before.values())
    total_after = sum(ind_after.values())
    persistence_detected = total_after > 0

    if total_before <= 0:
        status = "INCONCLUSIVE"
        confidence = 0.5
        effectiveness = 0.0
    elif total_after == 0:
        status = "VERIFIED_RESOLVED"
        confidence = round(0.7 + 0.3 * (len(neutralised) > 0), 3)
        effectiveness = 1.0
    elif total_after < total_before:
        status = "PARTIALLY_RESOLVED"
        effectiveness = round((total_before - total_after) / total_before, 3)
        confidence = round(0.5 + 0.3 * effectiveness, 3)
    else:
        status = "THREAT_PERSISTS"
        confidence = 0.6
        effectiveness = 0.0

    # legacy outcome vocabulary (kept for memory learning / analytics)
    outcome = {"VERIFIED_RESOLVED": "SUCCESS",
               "PARTIALLY_RESOLVED": "PARTIAL",
               "THREAT_PERSISTS": "THREAT_PERSISTS",
               "INCONCLUSIVE": "SUCCESS"}[status]

    evidence = []
    for name, cnt in ind_before.items():
        evidence.append(f"{name}: {cnt} before -> {ind_after.get(name, 0)} after")
    if neutralised:
        evidence.append(f"{len(neutralised)} indicator event(s) neutralised by "
                        f"'{response_action}' (simulated effect).")

    return {
        "verification_status": status,
        "outcome": outcome,
        "attack_type": attack_type,
        "verification_method": VERIFICATION_METHOD.get(attack_type, "generic"),
        "indicators_before": ind_before,
        "indicators_after": ind_after,
        "total_before": total_before,
        "total_after": total_after,
        "persistence_detected": persistence_detected,
        "verification_confidence": confidence,
        "effectiveness": effectiveness,
        "neutralised_event_ids": neutralised,
        "coverage_dimension": _coverage_dimension(response_action),
        "evidence": evidence,
    }
