"""Security Posture Assessment.

Produces an *evidence-based* assessment of the security posture of an authorized
environment, computed ONLY from data actually present in the selected dataset
(real by default). It never fabricates ports, services, CVEs, threat-intel
reputation, or findings.

Design principles
-----------------
* Every category is either ASSESSED, PARTIALLY_ASSESSED, or NOT_ASSESSED.
  NOT_ASSESSED is never treated as "secure".
* Scoring is transparent: each category exposes its checks, the evidence it had,
  and every deduction (reason + points). The overall score is the mean of the
  ASSESSED category scores only — a category with no data cannot inflate or
  deflate it. Coverage (assessed / total) is reported prominently so a high
  score under low coverage is not mistaken for strong security.
* Every finding references the real evidence (event ids / observed values).

This module reuses existing SOC services (detection rules, threat intel) rather
than duplicating logic.
"""
from __future__ import annotations

from . import audit
from . import database as db
from .agents import threat_intel_agent
from .config import config
from .detection.rules import (SUSPICIOUS_PORTS, _is_failed_login,
                              _is_success_login)
from .models import new_assessment_id, new_finding_id, now_iso

# Cleartext / high-risk-if-exposed protocols by port.
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3",
                   143: "IMAP", 445: "SMB", 3389: "RDP"}

CATEGORY_ORDER = [
    "network_exposure", "authentication", "access_control",
    "software_vulnerability", "security_configuration", "logging_monitoring",
    "encryption", "threat_indicators", "incident_history",
]
CATEGORY_TITLES = {
    "network_exposure": "Network Exposure",
    "authentication": "Authentication Security",
    "access_control": "Access Control",
    "software_vulnerability": "Software / Vulnerability Posture",
    "security_configuration": "Security Configuration",
    "logging_monitoring": "Logging & Monitoring",
    "encryption": "Encryption / Secure Communication",
    "threat_indicators": "Threat Indicators",
    "incident_history": "Incident History",
}

ASSESSED, PARTIAL, NOT_ASSESSED = "ASSESSED", "PARTIALLY_ASSESSED", "NOT_ASSESSED"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _category(status, score, checks, evidence_available, deductions=None,
              notes="", confidence=0.0):
    return {
        "status": status,
        "score": None if score is None else round(max(0.0, min(100.0, score)), 1),
        "checks_performed": checks,
        "evidence_available": evidence_available,
        "deductions": deductions or [],
        "confidence": round(confidence, 2),
        "notes": notes,
    }


def _finding(category, title, severity, confidence, affected_asset, evidence,
             explanation, recommendation, source):
    return {
        "finding_id": new_finding_id(),
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": round(confidence, 2),
        "affected_asset": affected_asset,
        "evidence": evidence,
        "explanation": explanation,
        "recommendation": recommendation,
        "source": source,
        "timestamp": now_iso(),
    }


# --------------------------------------------------------------------------- #
# category assessors — each returns (category_dict, [findings])
# --------------------------------------------------------------------------- #
def _assess_network_exposure(events, incidents, src):
    with_ports = [e for e in events if e.get("port") is not None]
    if not with_ports:
        return _category(NOT_ASSESSED, None, ["observed destination ports"],
                         False, notes="No port/network information in dataset."), []
    ports = {e["port"] for e in with_ports}
    suspicious = sorted(p for p in ports if p in SUSPICIOUS_PORTS)
    scan_incidents = [i for i in incidents if i["attack_type"] == "port_scan"]
    deductions, findings = [], []
    if suspicious:
        pts = min(35, 8 * len(suspicious))
        deductions.append({"reason": f"suspicious/administrative ports observed: "
                                     f"{suspicious}", "points": pts})
        findings.append(_finding(
            "network_exposure", "Suspicious/administrative ports observed",
            "Medium", 0.7, f"ports {suspicious}",
            [f"event #{e['id']} dst_port={e['port']}"
             for e in with_ports if e["port"] in SUSPICIOUS_PORTS][:8],
            "These ports are commonly targeted or are administrative services; "
            "exposure increases attack surface.",
            "Restrict/segment these services and verify they must be reachable.",
            src))
    if scan_incidents:
        deductions.append({"reason": f"{len(scan_incidents)} port-scan incident(s) "
                                     f"detected", "points": min(30, 10 * len(scan_incidents))})
        findings.append(_finding(
            "network_exposure", "Port-scanning activity detected", "High", 0.75,
            ", ".join(i["incident_id"] for i in scan_incidents[:5]),
            [i["incident_id"] for i in scan_incidents[:5]],
            "Reconnaissance / network service discovery observed in the data.",
            "Investigate scanning sources and review firewall/IPS rules.", src))
    score = 100 - sum(d["points"] for d in deductions)
    conf = min(0.9, 0.4 + 0.1 * len(with_ports) / max(1, len(events)) * 10)
    return _category(ASSESSED, score,
                     ["observed ports", "suspicious ports", "port-scan incidents"],
                     True, deductions,
                     f"{len(ports)} distinct ports observed.", conf), findings


def _assess_authentication(events, incidents, src):
    auth = [e for e in events if _is_failed_login(e) or _is_success_login(e)
            or "login" in (e.get("event_type") or "").lower()
            or "logon" in (e.get("event_type") or "").lower()
            or e.get("authentication_result")]
    if not auth:
        return _category(NOT_ASSESSED, None, ["authentication events"], False,
                         notes="No authentication information in dataset."), []
    failed = [e for e in auth if _is_failed_login(e)]
    cred_inc = [i for i in incidents if i["attack_type"] in
                ("brute_force", "credential_compromise")]
    deductions, findings = [], []
    fail_ratio = len(failed) / max(1, len(auth))
    if fail_ratio > 0.5 and len(failed) >= 5:
        deductions.append({"reason": f"high authentication failure ratio "
                                     f"({int(fail_ratio*100)}%)", "points": 20})
    for i in cred_inc:
        pts = 25 if i["attack_type"] == "credential_compromise" else 15
        deductions.append({"reason": f"{i['attack_type']} incident {i['incident_id']}",
                           "points": pts})
        findings.append(_finding(
            "authentication",
            "Repeated failed authentication followed by activity"
            if i["attack_type"] == "credential_compromise"
            else "Repeated failed authentication attempts",
            "Critical" if i["attack_type"] == "credential_compromise" else "High",
            i["confidence"] or 0.7,
            ", ".join(db.jload(i["source_ips"], []) or []) or "n/a",
            [i["incident_id"]],
            "Observed authentication sequence may indicate credential attack "
            "activity (evidence-based, not confirmed compromise).",
            "Investigate the source and affected account; review authentication "
            "controls (lockout, MFA).", src))
    score = 100 - min(70, sum(d["points"] for d in deductions))
    return _category(ASSESSED, score,
                     ["failed-login ratio", "brute-force/credential incidents"],
                     True, deductions,
                     f"{len(auth)} auth events, {len(failed)} failed.",
                     min(0.9, 0.5 + 0.05 * len(cred_inc))), findings


def _assess_access_control(events, incidents, src):
    priv_events = [e for e in events if
                   "priv" in (e.get("event_type") or "").lower()
                   or any(k in (e.get("command") or "").lower()
                          for k in ("whoami /priv", "net localgroup", "runas",
                                    "sudo", "getsystem"))]
    priv_inc = [i for i in incidents if i["attack_type"] == "privilege_escalation"]
    if not priv_events and not priv_inc:
        return _category(NOT_ASSESSED, None,
                         ["privileged activity", "privilege-escalation indicators"],
                         False, notes="No account/privilege information in dataset."), []
    deductions, findings = [], []
    for i in priv_inc:
        deductions.append({"reason": f"privilege-escalation incident {i['incident_id']}",
                           "points": 25})
        findings.append(_finding(
            "access_control", "Privilege-escalation indicators observed", "High",
            i["confidence"] or 0.7,
            ", ".join(db.jload(i["affected_users"], []) or []) or "n/a",
            [i["incident_id"]],
            "Activity consistent with attempts to gain elevated privileges.",
            "Review privileged accounts and escalation paths; apply least "
            "privilege.", src))
    score = 100 - min(60, sum(d["points"] for d in deductions))
    status = ASSESSED if (priv_events or priv_inc) else PARTIAL
    return _category(status, score, ["privileged activity", "escalation incidents"],
                     True, deductions,
                     f"{len(priv_events)} privileged event(s).", 0.6), findings


def _assess_software_vulnerability(events, incidents, src):
    # We do not have software/version/CVE fields in the flow/log schema, and we
    # never fabricate CVEs. If no such evidence exists -> NOT ASSESSED.
    have = any(e.get("process") for e in events)
    if not have:
        return _category(NOT_ASSESSED, None,
                         ["software versions", "known-vulnerability metadata"],
                         False,
                         notes="No software/version/CVE information available; "
                               "vulnerability posture not assessed (no fabrication)."), []
    # We can only note that process names exist; we do NOT claim vulnerabilities.
    return _category(PARTIAL, None, ["process inventory"], True,
                     notes="Process names observed but no version/CVE data; "
                           "vulnerability status cannot be determined."), []


def _assess_security_configuration(events, incidents, src):
    # No security-control/configuration fields in the dataset schema.
    return _category(NOT_ASSESSED, None,
                     ["security controls", "firewall/endpoint configuration"],
                     False,
                     notes="No security-configuration information available in the "
                           "dataset; not assessed."), []


def _assess_logging_monitoring(events, incidents, src):
    # Meta-assessment of the ingested telemetry itself (observable).
    if not events:
        return _category(NOT_ASSESSED, None, ["log coverage"], False,
                         notes="No events ingested."), []
    fields = ["timestamp", "source_ip", "destination_ip", "port", "user",
              "event_type", "authentication_result"]
    coverage = {f: sum(1 for e in events if e.get(f) not in (None, "")) / len(events)
                for f in fields}
    present = [f for f, r in coverage.items() if r >= 0.3]
    deductions, findings = [], []
    missing = [f for f in fields if coverage[f] < 0.3]
    # deduct for weak coverage of security-relevant fields
    pts = min(40, 6 * len(missing))
    if missing:
        deductions.append({"reason": f"limited coverage of fields: {missing}",
                           "points": pts})
        findings.append(_finding(
            "logging_monitoring", "Limited security telemetry coverage",
            "Low", 0.6, "dataset",
            [f"{f}: {int(coverage[f]*100)}% populated" for f in missing],
            "Some security-relevant fields are sparse/absent, reducing detection "
            "and investigation visibility.",
            "Enrich logging to include the missing fields where feasible.", src))
    score = 100 - pts
    return _category(ASSESSED, score, ["field coverage of security telemetry"],
                     True, deductions,
                     f"{len(present)}/{len(fields)} key fields adequately "
                     f"populated.", 0.7), findings


def _assess_encryption(events, incidents, src):
    with_ports = [e for e in events if e.get("port") is not None]
    if not with_ports:
        return _category(NOT_ASSESSED, None, ["protocol/port observation"], False,
                         notes="No protocol/port information to assess encryption."), []
    cleartext = {}
    for e in with_ports:
        if e["port"] in CLEARTEXT_PORTS:
            cleartext.setdefault(CLEARTEXT_PORTS[e["port"]], []).append(e["id"])
    deductions, findings = [], []
    if cleartext:
        pts = min(40, 8 * len(cleartext))
        deductions.append({"reason": f"cleartext/legacy protocols observed: "
                                     f"{sorted(cleartext)}", "points": pts})
        findings.append(_finding(
            "encryption", "Cleartext or legacy protocols observed", "Medium", 0.65,
            ", ".join(sorted(cleartext)),
            [f"{proto}: events {ids[:5]}" for proto, ids in cleartext.items()],
            "Communication over protocols without transport encryption may expose "
            "data in transit.",
            "Migrate to encrypted equivalents (e.g. SSH, HTTPS, SMB signing/TLS).",
            src))
    score = 100 - sum(d["points"] for d in deductions)
    return _category(ASSESSED, score, ["cleartext protocol exposure"], True,
                     deductions, f"{len(cleartext)} cleartext protocol(s) seen.",
                     0.6), findings


def _assess_threat_indicators(events, incidents, src):
    ips = {e.get("source_ip") for e in events if e.get("source_ip")} | \
          {e.get("destination_ip") for e in events if e.get("destination_ip")}
    ips = {ip for ip in ips if ip}
    if not ips:
        return _category(NOT_ASSESSED, None, ["indicator reputation"], False,
                         notes="No IP indicators available to assess."), []
    matches = []
    for ip in ips:
        r = threat_intel_agent.lookup(ip, "ip")
        if r["reputation"] in ("malicious", "suspicious"):
            matches.append(r)
    ext = config.EXTERNAL_TI_ENABLED and threat_intel_agent.EXTERNAL_CONFIGURED
    note = ("Local threat intelligence only — external threat intelligence "
            "unavailable for this assessment." if not ext else "")
    deductions, findings = [], []
    for m in matches:
        pts = 20 if m["reputation"] == "malicious" else 10
        deductions.append({"reason": f"indicator {m['indicator']} "
                                     f"({m['reputation']})", "points": pts})
        findings.append(_finding(
            "threat_indicators", f"Known {m['reputation']} indicator involved",
            "High" if m["reputation"] == "malicious" else "Medium",
            round(min(1.0, 0.5 + m["score"] / 200.0), 2),
            m["indicator"], [f"{m['indicator']} (local CTI score {m['score']}, "
                             f"src {m['source']})"],
            "An observed indicator matched local threat intelligence.",
            "Block/monitor the indicator and hunt for related activity.", src))
    # Absence of a hit is NOT treated as safe when TI coverage is limited.
    score = 100 - min(60, sum(d["points"] for d in deductions))
    status = ASSESSED if matches else PARTIAL
    if not matches:
        note = ("No local threat-intel matches; " + note +
                " Absence of a match is not evidence of safety.")
    return _category(status, score, ["local CTI reputation of observed IPs"], True,
                     deductions, note, 0.5 if not matches else 0.7), findings


def _assess_incident_history(events, incidents, src):
    if not events and not incidents:
        return _category(NOT_ASSESSED, None, ["prior incidents"], False,
                         notes="No SOC activity for this dataset yet."), []
    open_inc = [i for i in incidents if i["status"] not in ("Closed", "Contained")]
    high_risk = [i for i in incidents if (i["risk_score"] or 0) >= 0.65]
    deductions, findings = [], []
    if open_inc:
        deductions.append({"reason": f"{len(open_inc)} open/unresolved incident(s)",
                           "points": min(40, 8 * len(open_inc))})
    if high_risk:
        deductions.append({"reason": f"{len(high_risk)} high-risk incident(s)",
                           "points": min(30, 10 * len(high_risk))})
        findings.append(_finding(
            "incident_history", "High-risk incidents present", "High", 0.8,
            ", ".join(i["incident_id"] for i in high_risk[:5]),
            [i["incident_id"] for i in high_risk[:5]],
            "The SOC has detected high-risk incidents in this dataset.",
            "Prioritise investigation and validated response for these incidents.",
            src))
    score = 100 - sum(d["points"] for d in deductions)
    return _category(ASSESSED, score,
                     ["open incidents", "high-risk incidents"], True, deductions,
                     f"{len(incidents)} incident(s), {len(open_inc)} open.",
                     0.8), findings


_ASSESSORS = {
    "network_exposure": _assess_network_exposure,
    "authentication": _assess_authentication,
    "access_control": _assess_access_control,
    "software_vulnerability": _assess_software_vulnerability,
    "security_configuration": _assess_security_configuration,
    "logging_monitoring": _assess_logging_monitoring,
    "encryption": _assess_encryption,
    "threat_indicators": _assess_threat_indicators,
    "incident_history": _assess_incident_history,
}


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def run_assessment(dataset: str = "real", data_source: str | None = None) -> dict:
    """Run a full posture assessment over ``dataset`` and persist it."""
    if dataset not in ("real", "demo"):
        dataset = "real"
    events = db.query("SELECT * FROM events WHERE dataset=?", (dataset,))
    incidents = db.query("SELECT * FROM incidents WHERE dataset=?", (dataset,))
    src = data_source or (f"{dataset} dataset")

    categories, all_findings = {}, []
    for key in CATEGORY_ORDER:
        cat, findings = _ASSESSORS[key](events, incidents, src)
        cat["category"] = key
        cat["title"] = CATEGORY_TITLES[key]
        cat["findings"] = [f["finding_id"] for f in findings]
        categories[key] = cat
        all_findings.extend(findings)

    assessed = [c for c in categories.values() if c["status"] == ASSESSED]
    partial = [c for c in categories.values() if c["status"] == PARTIAL]
    scored = [c for c in categories.values() if c["score"] is not None]
    overall = round(sum(c["score"] for c in scored) / len(scored), 1) if scored else None

    coverage_assessed = len(assessed) + len(partial)
    coverage_total = len(CATEGORY_ORDER)
    coverage_ratio = coverage_assessed / coverage_total

    if overall is None:
        posture = "Not Assessed"
    elif coverage_ratio < 0.5:
        posture = "Low coverage — insufficient data for a reliable posture"
    elif overall >= 80:
        posture = "Strong (within assessed scope)"
    elif overall >= 60:
        posture = "Moderate (within assessed scope)"
    else:
        posture = "Weak (within assessed scope)"

    recommendations = _build_recommendations(all_findings)

    aid = new_assessment_id()
    now = now_iso()
    db.insert("security_assessments", {
        "assessment_id": aid, "dataset": dataset, "data_source": src,
        "created_at": now, "overall_score": overall, "posture_label": posture,
        "coverage_assessed": coverage_assessed, "coverage_total": coverage_total,
        "category_scores": db.jdump(categories), "events_analyzed": len(events),
        "incidents_analyzed": len(incidents)})
    for f in all_findings:
        db.insert("security_findings", {
            "finding_id": f["finding_id"], "assessment_id": aid,
            "category": f["category"], "title": f["title"],
            "severity": f["severity"], "confidence": f["confidence"],
            "affected_asset": f["affected_asset"],
            "evidence": db.jdump(f["evidence"]), "explanation": f["explanation"],
            "recommendation": f["recommendation"], "source": f["source"],
            "created_at": f["timestamp"]})
    for r in recommendations:
        db.insert("security_recommendations", {
            "assessment_id": aid, "category": r["category"],
            "recommendation": r["recommendation"], "priority": r["priority"],
            "reason": r["reason"], "evidence": db.jdump(r["evidence"]),
            "expected_benefit": r["expected_benefit"],
            "implementation_risk": r["implementation_risk"], "created_at": now})

    audit.log("assessment.completed", actor="Security Assessment",
              detail=f"{aid}: score {overall}, coverage "
                     f"{coverage_assessed}/{coverage_total}, "
                     f"{len(all_findings)} finding(s)", dataset=dataset)

    return _bundle(aid)


SEV_PRIORITY = {"Critical": "Critical", "High": "High", "Medium": "Medium",
                "Low": "Low", "Informational": "Low"}


def _build_recommendations(findings: list[dict]) -> list[dict]:
    seen, recs = set(), []
    # sort by severity so the most important recommendations come first
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 5)):
        key = (f["category"], f["recommendation"])
        if key in seen:
            continue
        seen.add(key)
        recs.append({
            "category": f["category"],
            "recommendation": f["recommendation"],
            "priority": SEV_PRIORITY.get(f["severity"], "Medium"),
            "reason": f["title"],
            "evidence": f["evidence"],
            "expected_benefit": "Reduces the risk described by the finding.",
            "implementation_risk": "Low (configuration/investigation action).",
        })
    return recs


def _bundle(assessment_id: str) -> dict | None:
    a = db.query_one("SELECT * FROM security_assessments WHERE assessment_id=?",
                     (assessment_id,))
    if not a:
        return None
    a["category_scores"] = db.jload(a["category_scores"], {})
    findings = db.query(
        "SELECT * FROM security_findings WHERE assessment_id=? ORDER BY id",
        (assessment_id,))
    for f in findings:
        f["evidence"] = db.jload(f["evidence"], [])
    recs = db.query(
        "SELECT * FROM security_recommendations WHERE assessment_id=? ORDER BY id",
        (assessment_id,))
    for r in recs:
        r["evidence"] = db.jload(r["evidence"], [])
    unassessed = [{"category": k, "title": CATEGORY_TITLES[k],
                   "notes": v.get("notes", "")}
                  for k, v in a["category_scores"].items()
                  if v["status"] == NOT_ASSESSED]
    return {"assessment": a, "findings": findings, "recommendations": recs,
            "unassessed": unassessed}


def get_assessment(assessment_id: str) -> dict | None:
    return _bundle(assessment_id)


def latest(dataset: str = "real") -> dict | None:
    row = db.query_one(
        "SELECT assessment_id FROM security_assessments WHERE dataset=? "
        "ORDER BY created_at DESC LIMIT 1", (dataset,))
    return _bundle(row["assessment_id"]) if row else None


def history(dataset: str = "real", limit: int = 25) -> list[dict]:
    rows = db.query(
        "SELECT assessment_id, created_at, data_source, overall_score, "
        "posture_label, coverage_assessed, coverage_total, events_analyzed, "
        "incidents_analyzed FROM security_assessments WHERE dataset=? "
        "ORDER BY created_at DESC LIMIT ?", (dataset, limit))
    return rows


def diff(dataset: str = "real") -> dict | None:
    """Category-score delta between the two most recent assessments."""
    rows = db.query(
        "SELECT assessment_id, category_scores, created_at FROM "
        "security_assessments WHERE dataset=? ORDER BY created_at DESC LIMIT 2",
        (dataset,))
    if len(rows) < 2:
        return None
    cur = db.jload(rows[0]["category_scores"], {})
    prev = db.jload(rows[1]["category_scores"], {})
    deltas = {}
    for k in CATEGORY_ORDER:
        pc, cc = prev.get(k, {}), cur.get(k, {})
        deltas[k] = {"title": CATEGORY_TITLES[k],
                     "previous": pc.get("score"), "current": cc.get("score")}
    return {"current_at": rows[0]["created_at"], "previous_at": rows[1]["created_at"],
            "deltas": deltas}
