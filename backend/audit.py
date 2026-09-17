"""Append-only audit trail helper."""
from __future__ import annotations

from . import database as db
from .models import now_iso
from .security import sanitize_text


def log(action: str, *, incident_id: str | None = None, actor: str = "system",
        detail: str = "", dataset: str | None = None) -> None:
    db.insert(
        "audit_logs",
        {
            "ts": now_iso(),
            "incident_id": incident_id,
            "actor": actor,
            "action": sanitize_text(action, 200),
            "detail": sanitize_text(detail, 2000),
            "dataset": dataset,
        },
    )


def for_incident(incident_id: str) -> list[dict]:
    return db.query(
        "SELECT * FROM audit_logs WHERE incident_id=? ORDER BY id ASC",
        (incident_id,),
    )


def recent(limit: int = 200, dataset: str | None = None) -> list[dict]:
    if dataset:
        return db.query(
            "SELECT * FROM audit_logs WHERE dataset=? ORDER BY id DESC LIMIT ?",
            (dataset, limit),
        )
    return db.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
