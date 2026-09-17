"""Ingestion + normalization of security events.

Supports CSV, JSON (array or NDJSON), and simple syslog / key=value lines.
Everything is coerced into the canonical normalized event schema
(``models.EVENT_FIELDS``). Raw content is preserved in ``raw_event`` and is
always treated as data (see ``security.py``).
"""
from __future__ import annotations

import csv
import datetime as _dt
import io
import json
import re

from . import database as db
from .config import config
from .models import EVENT_FIELDS, FIELD_ALIASES, empty_event, new_batch_id, now_iso
from .security import event_injection_signals, sanitize_text

_INT_FIELDS = {"port", "bytes"}


class IngestionError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def parse_csv(text: str) -> list[dict]:
    text = text.lstrip("﻿")
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(r) for r in reader]
    except csv.Error as exc:
        raise IngestionError(f"Invalid CSV: {exc}") from exc
    if not rows:
        raise IngestionError("CSV contained no data rows.")
    return rows


def parse_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        raise IngestionError("Empty JSON document.")
    # Try a single JSON value first.
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if isinstance(obj, dict):
            # allow {"events": [...]}
            for key in ("events", "records", "data", "logs"):
                if isinstance(obj.get(key), list):
                    return [x for x in obj[key] if isinstance(x, dict)]
            return [obj]
    except json.JSONDecodeError:
        pass
    # Fall back to NDJSON (one JSON object per line).
    rows = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IngestionError(f"Invalid JSON on line {i}: {exc}") from exc
        if isinstance(obj, dict):
            rows.append(obj)
    if not rows:
        raise IngestionError("No JSON objects found.")
    return rows


_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def parse_syslog(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec: dict = {"raw_event": line}
        m = _SYSLOG_RE.match(line)
        if m:
            rec["timestamp"] = m.group("ts")
            rec["host"] = m.group("host")
            body = m.group("msg")
        else:
            body = line
        for k, v in _KV_RE.findall(body):
            rec[k.lower()] = v.strip('"')
        rows.append(rec)
    if not rows:
        raise IngestionError("No syslog lines found.")
    return rows


def parse(content: str, fmt: str) -> list[dict]:
    fmt = (fmt or "").lower()
    if fmt == "csv":
        return parse_csv(content)
    if fmt == "json":
        return parse_json(content)
    if fmt in ("syslog", "log", "txt"):
        return parse_syslog(content)
    raise IngestionError(f"Unsupported format: {fmt}")


def detect_format(filename: str, content: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".json") or name.endswith(".ndjson"):
        return "json"
    if name.endswith((".log", ".syslog", ".txt")):
        return "syslog"
    stripped = content.lstrip()
    if stripped.startswith(("[", "{")):
        return "json"
    if "," in content.splitlines()[0] if content.splitlines() else False:
        return "csv"
    return "syslog"


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def _coerce_int(value):
    if value in (None, "", "-"):
        return None
    try:
        return int(float(str(value).replace(",", "").strip()))
    except (ValueError, TypeError):
        return None


def _normalize_timestamp(value) -> str:
    if value in (None, ""):
        return now_iso()
    s = str(value).strip()
    # epoch seconds / millis
    if re.fullmatch(r"\d{10}", s):
        return _dt.datetime.fromtimestamp(int(s), _dt.timezone.utc).isoformat()
    if re.fullmatch(r"\d{13}", s):
        return _dt.datetime.fromtimestamp(int(s) / 1000, _dt.timezone.utc).isoformat()
    # Syslog RFC3164 timestamps omit the year ("Sep 15 10:31:02"). Parsing them
    # bare is deprecated (defaults to 1900 and warns), so prepend the current
    # year explicitly and parse with a year-aware format — no warning, no
    # ambiguity, and no timezone shift.
    if re.match(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", s):
        year = _dt.datetime.now().year
        try:
            return _dt.datetime.strptime(f"{year} {s}",
                                         "%Y %b %d %H:%M:%S").isoformat()
        except ValueError:
            pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            return _dt.datetime.strptime(s, fmt).isoformat()
        except ValueError:
            continue
    # ISO fallback
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return s  # keep original string; sortable enough for display


def canonical_field(raw_key) -> str | None:
    """Return the canonical schema field a raw column maps to, or None."""
    if raw_key is None:
        return None
    norm_key = str(raw_key).strip().lower().replace(" ", "_")
    return norm_key if norm_key in EVENT_FIELDS else FIELD_ALIASES.get(norm_key)


def normalize_row(raw: dict) -> dict:
    event = empty_event()
    extras = {}
    for key, value in raw.items():
        if key is None:
            continue
        norm_key = str(key).strip().lower().replace(" ", "_")
        target = norm_key if norm_key in EVENT_FIELDS else FIELD_ALIASES.get(norm_key)
        if target:
            event[target] = value
        else:
            extras[norm_key] = value

    event["timestamp"] = _normalize_timestamp(event.get("timestamp"))
    for f in _INT_FIELDS:
        event[f] = _coerce_int(event[f])
    for f in ("source", "host", "user", "source_ip", "destination_ip",
              "protocol", "event_type", "action", "status", "severity",
              "process", "command", "authentication_result", "event_id",
              "label"):
        if event[f] is not None:
            event[f] = sanitize_text(event[f], 500).strip() or None

    if not event.get("raw_event"):
        event["raw_event"] = sanitize_text(json.dumps({**raw}, default=str), 2000)
    else:
        event["raw_event"] = sanitize_text(event["raw_event"], 2000)

    # normalize authentication_result / status vocabulary a little
    ar = (event.get("authentication_result") or "").lower()
    if ar in ("fail", "failed", "failure", "denied"):
        event["authentication_result"] = "failure"
    elif ar in ("success", "succeeded", "ok", "allowed", "accept"):
        event["authentication_result"] = "success"

    return event


# --------------------------------------------------------------------------- #
# Storage + stats
# --------------------------------------------------------------------------- #
def store_events(events: list[dict], dataset: str, batch_id: str) -> int:
    if not events:
        return 0
    cols = ["dataset", "batch_id"] + EVENT_FIELDS
    placeholders = ", ".join(["?"] * len(cols))
    sql = f"INSERT INTO events ({', '.join(cols)}) VALUES ({placeholders})"
    rows = []
    for ev in events[: config.MAX_EVENTS]:
        rows.append([dataset, batch_id] + [ev.get(f) for f in EVENT_FIELDS])
    db.executemany(sql, rows)
    return len(rows)


def _raw_has_timestamp(raw: dict) -> bool:
    """True if the source row has a non-empty value in a timestamp column."""
    for k, v in raw.items():
        if canonical_field(k) == "timestamp" and str(v or "").strip():
            return True
    return False


def _row_is_usable(raw: dict, event: dict) -> bool:
    """A row is usable if it carries at least one real security signal.

    Empty / junk rows (no timestamp VALUE, no ip/user/host/type/process value)
    are rejected rather than stored — this keeps detection honest.
    """
    signal = any(event.get(f) for f in
                 ("source_ip", "destination_ip", "user", "host",
                  "event_type", "process", "command", "action"))
    return _raw_has_timestamp(raw) or signal


def build_quality_report(raw_rows: list[dict], events: list[dict],
                         kept_flags: list[bool]) -> dict:
    """Produce an analyst-facing data-quality report for an upload."""
    detected: dict[str, int] = {}
    normalized_map: dict[str, str] = {}
    for raw in raw_rows:
        for k in raw:
            if k is None:
                continue
            key = str(k)
            detected[key] = detected.get(key, 0) + 1
            cf = canonical_field(k)
            if cf and key not in normalized_map:
                normalized_map[key] = cf

    missing_ts = missing_ip = missing_user = 0
    seen, duplicates = set(), 0
    for raw, ev in zip(raw_rows, events):
        if not _raw_has_timestamp(raw):
            missing_ts += 1
        if not ev.get("source_ip") and not ev.get("destination_ip"):
            missing_ip += 1
        if not ev.get("user"):
            missing_user += 1
        sig = (ev.get("timestamp"), ev.get("event_type"), ev.get("user"),
               ev.get("source_ip"), ev.get("host"), ev.get("command"))
        if sig in seen:
            duplicates += 1
        else:
            seen.add(sig)

    total = len(raw_rows)
    valid = sum(1 for f in kept_flags if f)
    rejected = total - valid
    return {
        "total_records": total,
        "valid_records": valid,
        "invalid_records": rejected,
        "rejected_records": rejected,
        "missing_timestamps": missing_ts,
        "missing_ip_addresses": missing_ip,
        "missing_users": missing_user,
        "duplicate_records": duplicates,
        "detected_fields": sorted(detected.keys()),
        "normalized_fields": normalized_map,
        "unmapped_fields": sorted(k for k in detected if k not in normalized_map),
    }


def ingest(content: str, filename: str, dataset: str = "real",
           fmt: str | None = None) -> dict:
    """Parse -> normalize -> data-quality profile -> store. Returns a summary."""
    if dataset not in ("real", "demo"):
        raise IngestionError("dataset must be 'real' or 'demo'")
    fmt = fmt or detect_format(filename, content)
    raw_rows = parse(content, fmt)
    if len(raw_rows) > config.MAX_EVENTS:
        raw_rows = raw_rows[: config.MAX_EVENTS]
    events = [normalize_row(r) for r in raw_rows]
    kept_flags = [_row_is_usable(raw, ev) for raw, ev in zip(raw_rows, events)]
    quality = build_quality_report(raw_rows, events, kept_flags)

    kept_events = [ev for ev, keep in zip(events, kept_flags) if keep]
    if not kept_events:
        raise IngestionError(
            "No usable events found (all rows were empty or unrecognised).")

    batch_id = new_batch_id()
    stored = store_events(kept_events, dataset, batch_id)
    stats = summarize(kept_events)
    stats.update({"batch_id": batch_id, "format": fmt, "stored": stored,
                  "dataset": dataset, "filename": filename,
                  "data_quality": quality})
    return stats


def summarize(events: list[dict]) -> dict:
    if not events:
        return {
            "count": 0, "time_range": None, "event_types": {}, "unique_users": 0,
            "unique_hosts": 0, "source_ips": 0, "destination_ips": 0,
            "failed_logins": 0, "suspicious_events": 0, "injection_flags": 0,
        }
    timestamps = sorted(str(e.get("timestamp")) for e in events if e.get("timestamp"))
    types: dict[str, int] = {}
    users, hosts, sips, dips = set(), set(), set(), set()
    failed = suspicious = injection = 0
    for e in events:
        t = e.get("event_type") or "unknown"
        types[t] = types.get(t, 0) + 1
        if e.get("user"):
            users.add(e["user"])
        if e.get("host"):
            hosts.add(e["host"])
        if e.get("source_ip"):
            sips.add(e["source_ip"])
        if e.get("destination_ip"):
            dips.add(e["destination_ip"])
        if (e.get("authentication_result") == "failure"
                or (e.get("status") or "").lower() in ("failure", "failed", "denied")):
            failed += 1
        sev = (e.get("severity") or "").lower()
        if sev in ("high", "critical") or (e.get("event_type") or "").lower() in (
            "malware", "exfiltration", "privilege_escalation", "port_scan"):
            suspicious += 1
        if event_injection_signals(e):
            injection += 1
    return {
        "count": len(events),
        "time_range": {"start": timestamps[0], "end": timestamps[-1]}
        if timestamps else None,
        "event_types": dict(sorted(types.items(), key=lambda kv: -kv[1])),
        "unique_users": len(users),
        "unique_hosts": len(hosts),
        "source_ips": len(sips),
        "destination_ips": len(dips),
        "failed_logins": failed,
        "suspicious_events": suspicious,
        "injection_flags": injection,
    }
