"""Threat Intelligence Agent.

Abstraction over indicator reputation lookups. For this prototype it uses a
LOCAL sample dataset seeded into the ``threat_intelligence`` table. External
providers (VirusTotal / AbuseIPDB / OTX / MISP) are intentionally NOT called
unless configured; when nothing is configured we say so rather than fabricate.
"""
from __future__ import annotations

import json

from .. import database as db
from ..config import DATA_DIR

_seeded = False

# Set to True automatically only if a real provider is configured (none here).
EXTERNAL_CONFIGURED = False


def seed_from_file() -> int:
    global _seeded
    path = DATA_DIR / "threat_intel.json"
    if not path.exists():
        _seeded = True
        return 0
    existing = db.scalar("SELECT COUNT(*) FROM threat_intelligence") or 0
    if existing:
        _seeded = True
        return existing
    data = json.loads(path.read_text(encoding="utf-8"))
    from ..models import now_iso
    for ind in data.get("indicators", []):
        db.insert("threat_intelligence", {
            "indicator": ind["indicator"],
            "indicator_type": ind.get("indicator_type", "ip"),
            "reputation": ind.get("reputation", "unknown"),
            "score": ind.get("score", 0),
            "source": ind.get("source", "sample"),
            "tags": ind.get("tags", ""),
            "last_seen": now_iso(),
        })
    _seeded = True
    return len(data.get("indicators", []))


def lookup(indicator: str, indicator_type: str = "ip") -> dict:
    if not _seeded:
        seed_from_file()
    row = db.query_one(
        "SELECT * FROM threat_intelligence WHERE indicator=? AND indicator_type=?",
        (indicator, indicator_type),
    )
    if row:
        score = row["score"] or 0
        # risk_contribution: how many of the 10 risk points TI would add.
        return {
            "indicator": indicator, "type": indicator_type,
            "reputation": row["reputation"], "score": score,
            "confidence": round(min(1.0, 0.4 + score / 150.0), 2),
            "source": row["source"], "tags": row["tags"],
            "first_seen": row["last_seen"], "last_seen": row["last_seen"],
            "risk_contribution": round((score / 100.0) * 10, 1),
            "provider": "local", "external_configured": EXTERNAL_CONFIGURED,
            "configured": True,
        }
    return {
        "indicator": indicator, "type": indicator_type,
        "reputation": "unknown", "score": 0, "confidence": 0.0,
        "source": "local", "tags": "", "first_seen": None, "last_seen": None,
        "risk_contribution": 0.0, "provider": "local",
        "external_configured": EXTERNAL_CONFIGURED, "configured": True,
        "note": "Local intelligence only — no local match.",
    }


def assess(ctx) -> dict:
    """Produce the Threat-Intel agent assessment for an incident context."""
    if not _seeded:
        seed_from_file()

    matches = []
    worst = 0
    for ip in ctx.source_ips | ctx.destination_ips:
        if not ip:
            continue
        res = lookup(ip, "ip")
        if res["reputation"] in ("malicious", "suspicious"):
            matches.append(res)
            worst = max(worst, res["score"])

    if not EXTERNAL_CONFIGURED and not matches:
        # No external CTI + no local hit -> be explicit, do not fabricate.
        return {
            "agent": "Threat Intel Agent",
            "verdict": "No confirmed malicious reputation",
            "confidence": 0.4,
            "rationale": ("No local indicator match. External threat "
                          "intelligence not configured."),
            "evidence_refs": [],
            "matches": [],
        }

    if matches:
        conf = min(0.97, 0.5 + worst / 200.0 + 0.1 * (len(matches) - 1))
        names = ", ".join(f"{m['indicator']} ({m['reputation']}, {m['score']})"
                          for m in matches[:4])
        return {
            "agent": "Threat Intel Agent",
            "verdict": "Malicious infrastructure involved"
            if worst >= 80 else "Suspicious infrastructure involved",
            "confidence": round(conf, 2),
            "rationale": f"Local CTI match: {names}.",
            "evidence_refs": [],
            "matches": matches,
        }

    return {
        "agent": "Threat Intel Agent",
        "verdict": "No confirmed malicious reputation",
        "confidence": 0.45,
        "rationale": "Indicators present but no reputation hit in local CTI.",
        "evidence_refs": [],
        "matches": [],
    }
