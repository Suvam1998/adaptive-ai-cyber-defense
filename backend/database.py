"""SQLite database layer for the AI-SOC.

A single shared connection is used with a re-entrant lock. WAL mode is enabled
so the demo background task and API requests can read/write concurrently.

Design notes
------------
* ``events`` carry a ``dataset`` column ('real' | 'demo') so real uploaded data
  and synthetic demo data are never mixed in any query.
* ``audit_logs`` is treated as append-only from application code (no UPDATE /
  DELETE helpers are exposed). A DB trigger blocks updates/deletes as defence
  in depth against accidental mutation from the normal application.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Iterable

from .config import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset         TEXT NOT NULL DEFAULT 'real',      -- 'real' | 'demo'
    batch_id        TEXT,
    timestamp       TEXT NOT NULL,
    event_id        TEXT,
    source          TEXT,
    host            TEXT,
    user            TEXT,
    source_ip       TEXT,
    destination_ip  TEXT,
    port            INTEGER,
    protocol        TEXT,
    event_type      TEXT,
    action          TEXT,
    status          TEXT,
    severity        TEXT,
    process         TEXT,
    command         TEXT,
    bytes           INTEGER,
    authentication_result TEXT,
    label           TEXT,
    raw_event       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_dataset  ON events(dataset);
CREATE INDEX IF NOT EXISTS idx_events_batch    ON events(batch_id);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_srcip    ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user     ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_host     ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT UNIQUE NOT NULL,
    dataset         TEXT NOT NULL DEFAULT 'real',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'New',       -- New/Investigating/Awaiting Approval/Contained/Closed
    stage           TEXT NOT NULL DEFAULT 'Detection',
    severity        TEXT NOT NULL DEFAULT 'Medium',
    risk_score      REAL DEFAULT 0.0,                  -- 0..1
    confidence      REAL DEFAULT 0.0,                  -- 0..1
    consensus       REAL DEFAULT 0.0,                  -- 0..1
    attack_type     TEXT,
    detection_reason TEXT,
    affected_hosts  TEXT,                              -- JSON list
    affected_users  TEXT,                              -- JSON list
    source_ips      TEXT,                              -- JSON list
    destination_ips TEXT,                              -- JSON list
    mitre           TEXT,                              -- JSON list of technique dicts
    evidence_count  INTEGER DEFAULT 0,
    recommended_action TEXT,
    autonomy_level  INTEGER DEFAULT 1,
    autonomy_decision TEXT,
    anomaly_score   REAL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_inc_dataset  ON incidents(dataset);
CREATE INDEX IF NOT EXISTS idx_inc_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_sev      ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_created  ON incidents(created_at);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT NOT NULL,
    event_ref       INTEGER,                           -- FK to events.id (nullable)
    kind            TEXT,                              -- 'event','entity','signal','intel','history'
    label           TEXT,
    detail          TEXT,
    weight          REAL DEFAULT 0.0,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ev_incident ON evidence(incident_id);

CREATE TABLE IF NOT EXISTS agent_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT NOT NULL,
    agent           TEXT NOT NULL,
    verdict         TEXT,
    confidence      REAL DEFAULT 0.0,
    rationale       TEXT,
    evidence_refs   TEXT,                              -- JSON list
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aa_incident ON agent_assessments(incident_id);

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,                     -- ip/domain/hash
    reputation      TEXT,                              -- malicious/suspicious/clean/unknown
    score           INTEGER DEFAULT 0,                 -- 0..100
    source          TEXT,
    tags            TEXT,
    last_seen       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_intelligence(indicator);

CREATE TABLE IF NOT EXISTS responses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id     TEXT UNIQUE NOT NULL,
    incident_id     TEXT NOT NULL,
    action          TEXT NOT NULL,
    target          TEXT,
    reason          TEXT,
    evidence_summary TEXT,
    response_risk   TEXT,                              -- low/medium/high
    expected_outcome TEXT,
    rollback        TEXT,
    status          TEXT DEFAULT 'planned',            -- planned/validated/awaiting_approval/approved/executed/failed/rejected
    requires_approval INTEGER DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resp_incident ON responses(incident_id);
CREATE INDEX IF NOT EXISTS idx_resp_status   ON responses(status);

CREATE TABLE IF NOT EXISTS response_validation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id     TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    evidence_sufficient INTEGER,
    confidence_ok   INTEGER,
    agents_agree    INTEGER,
    proportional    INTEGER,
    business_impact_ok INTEGER,
    rollback_ok     INTEGER,
    decision        TEXT,                              -- APPROVED/REJECTED/NEEDS_APPROVAL
    detail          TEXT,                              -- JSON
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_outcomes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id     TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    indicators_before INTEGER,
    indicators_after  INTEGER,
    outcome         TEXT,                              -- SUCCESS/THREAT_PERSISTS/PARTIAL
    effectiveness   REAL,                              -- 0..1
    detail          TEXT,
    created_at      TEXT NOT NULL
);

-- Simulated response effects. Kept SEPARATE from `events` so original security
-- evidence is never mutated: an effect is a *predicate* describing what the
-- action would neutralise, not an edit of the forensic record.
CREATE TABLE IF NOT EXISTS response_effects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id     TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    action          TEXT,
    target          TEXT,
    effect          TEXT,                              -- human-readable effect
    coverage        TEXT,                              -- which entity dimension
    neutralized_event_ids TEXT,                        -- JSON list of event ids
    neutralized_count INTEGER DEFAULT 0,
    simulated       INTEGER DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reffect_incident ON response_effects(incident_id);

CREATE TABLE IF NOT EXISTS memory (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    experience_id   TEXT UNIQUE NOT NULL,
    attack_type     TEXT,
    indicators      TEXT,                              -- JSON
    strategy        TEXT,                              -- the response action tried
    outcome         TEXT,                              -- SUCCESS/THREAT_PERSISTS/PARTIAL
    effectiveness   REAL,
    confidence      REAL DEFAULT 0.5,                  -- learned confidence 0..1
    trust_score     REAL DEFAULT 0.5,
    validation_status TEXT DEFAULT 'trusted',          -- trusted/under_review/revoked
    source          TEXT,                              -- 'demo' | 'real' | 'seed'
    provenance      TEXT,                              -- JSON audit of origin
    analyst_decision TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_attack ON memory(attack_type);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    incident_id     TEXT,
    actor           TEXT,                              -- 'system'/'orchestrator'/'analyst'/agent name
    action          TEXT NOT NULL,
    detail          TEXT,
    dataset         TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_logs(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

-- Defence in depth: make audit_logs effectively append-only.
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

CREATE TABLE IF NOT EXISTS security_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   TEXT UNIQUE NOT NULL,
    dataset         TEXT NOT NULL DEFAULT 'real',
    data_source     TEXT,
    created_at      TEXT NOT NULL,
    overall_score   REAL,                              -- 0..100 (assessed cats only)
    posture_label   TEXT,                              -- e.g. 'Moderate', 'Low coverage'
    coverage_assessed INTEGER,                         -- # categories assessed
    coverage_total  INTEGER,                           -- # categories total
    category_scores TEXT,                              -- JSON: transparent breakdown
    events_analyzed INTEGER,
    incidents_analyzed INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sa_dataset ON security_assessments(dataset);
CREATE INDEX IF NOT EXISTS idx_sa_created ON security_assessments(created_at);

CREATE TABLE IF NOT EXISTS security_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL,
    assessment_id   TEXT NOT NULL,
    category        TEXT,
    title           TEXT,
    severity        TEXT,                              -- Critical/High/Medium/Low/Informational
    confidence      REAL,
    affected_asset  TEXT,
    evidence        TEXT,                              -- JSON list of evidence refs
    explanation     TEXT,
    recommendation  TEXT,
    source          TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sf_assessment ON security_findings(assessment_id);

CREATE TABLE IF NOT EXISTS security_recommendations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id   TEXT NOT NULL,
    category        TEXT,
    recommendation  TEXT,
    priority        TEXT,
    reason          TEXT,
    evidence        TEXT,
    expected_benefit TEXT,
    implementation_risk TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sr_assessment ON security_recommendations(assessment_id);

CREATE TABLE IF NOT EXISTS demo_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    status          TEXT NOT NULL DEFAULT 'stopped',   -- stopped/running/paused
    scenario        TEXT,
    started_at      TEXT,
    updated_at      TEXT,
    events_generated INTEGER DEFAULT 0,
    incidents_generated INTEGER DEFAULT 0
);
INSERT OR IGNORE INTO demo_state (id, status) VALUES (1, 'stopped');
"""


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                _conn = sqlite3.connect(
                    config.DATABASE_PATH, check_same_thread=False, timeout=30
                )
                _conn.row_factory = sqlite3.Row
                _conn.execute("PRAGMA journal_mode=WAL;")
                _conn.execute("PRAGMA foreign_keys=ON;")
                _conn.executescript(SCHEMA)
                _migrate(_conn)
                _conn.commit()
    return _conn


# Columns added after the initial release. Applied idempotently on connect so
# existing soc.db files upgrade cleanly without a manual migration step.
_ADDED_COLUMNS = {
    "events": [("label", "TEXT")],
    "incidents": [("detection_method", "TEXT DEFAULT 'rule'")],
    "response_validation": [("target_valid", "INTEGER"),
                            ("threat_active", "INTEGER")],
    "response_outcomes": [("verification_method", "TEXT"),
                          ("verification_confidence", "REAL"),
                          ("persistence_detected", "INTEGER"),
                          ("evidence", "TEXT")],
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, cols in _ADDED_COLUMNS.items():
        existing = {r[1] for r in conn.execute(
            f"PRAGMA table_info({table})").fetchall()}
        for name, decl in cols:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_db() -> None:
    get_conn()


def execute(sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
    conn = get_conn()
    with _lock:
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur


def executemany(sql: str, seq: Iterable[Iterable[Any]]) -> None:
    conn = get_conn()
    with _lock:
        conn.executemany(sql, [tuple(p) for p in seq])
        conn.commit()


def query(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    conn = get_conn()
    with _lock:
        cur = conn.execute(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]


def query_one(sql: str, params: Iterable[Any] = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def scalar(sql: str, params: Iterable[Any] = ()) -> Any:
    row = query_one(sql, params)
    if not row:
        return None
    return next(iter(row.values()))


def insert(table: str, data: dict) -> int:
    cols = ", ".join(data.keys())
    ph = ", ".join(["?"] * len(data))
    cur = execute(
        f"INSERT INTO {table} ({cols}) VALUES ({ph})", list(data.values())
    )
    return cur.lastrowid


def jdump(obj: Any) -> str:
    return json.dumps(obj, default=str)


def jload(text: str | None, default: Any = None):
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


def reset_dataset(dataset: str) -> None:
    """Delete all rows belonging to a dataset ('real' or 'demo').

    audit_logs are append-only; we do not delete them here.
    """
    conn = get_conn()
    with _lock:
        inc_ids = [
            r["incident_id"]
            for r in conn.execute(
                "SELECT incident_id FROM incidents WHERE dataset=?", (dataset,)
            ).fetchall()
        ]
        assess_ids = [
            r["assessment_id"]
            for r in conn.execute(
                "SELECT assessment_id FROM security_assessments WHERE dataset=?",
                (dataset,)).fetchall()
        ]
        conn.execute("DELETE FROM security_assessments WHERE dataset=?", (dataset,))
        for aid in assess_ids:
            conn.execute("DELETE FROM security_findings WHERE assessment_id=?", (aid,))
            conn.execute("DELETE FROM security_recommendations WHERE assessment_id=?",
                         (aid,))
        conn.execute("DELETE FROM events WHERE dataset=?", (dataset,))
        conn.execute("DELETE FROM incidents WHERE dataset=?", (dataset,))
        for tbl in (
            "evidence",
            "agent_assessments",
            "responses",
            "response_validation",
            "response_outcomes",
            "response_effects",
        ):
            for iid in inc_ids:
                conn.execute(f"DELETE FROM {tbl} WHERE incident_id=?", (iid,))
        conn.commit()
