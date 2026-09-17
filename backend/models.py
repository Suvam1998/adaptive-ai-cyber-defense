"""Normalized event schema and small shared helpers."""
from __future__ import annotations

import datetime as _dt
import uuid

# Canonical normalized event field order.
EVENT_FIELDS = [
    "timestamp",
    "event_id",
    "source",
    "host",
    "user",
    "source_ip",
    "destination_ip",
    "port",
    "protocol",
    "event_type",
    "action",
    "status",
    "severity",
    "process",
    "command",
    "bytes",
    "authentication_result",
    "label",          # ground-truth label from a labelled dataset (e.g. CIC-IDS)
    "raw_event",
]

# Common aliases mapped to canonical field names during normalization.
FIELD_ALIASES = {
    "time": "timestamp",
    "datetime": "timestamp",
    "date": "timestamp",
    "@timestamp": "timestamp",
    "ts": "timestamp",
    "event_time": "timestamp",
    "eventtime": "timestamp",
    "log_time": "timestamp",
    "logtime": "timestamp",
    "created": "timestamp",
    "eventid": "event_id",
    "id": "event_id",
    "username": "user",
    "account": "user",
    "accountname": "user",
    "account_name": "user",
    "user_name": "user",
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "sourceip": "source_ip",
    "sourceaddress": "source_ip",
    "source_address": "source_ip",
    "src_addr": "source_ip",
    "ip": "source_ip",
    "client_ip": "source_ip",
    "clientip": "source_ip",
    "dst_ip": "destination_ip",
    "dstip": "destination_ip",
    "destip": "destination_ip",
    "destinationip": "destination_ip",
    "destinationaddress": "destination_ip",
    "destination_address": "destination_ip",
    "dst_addr": "destination_ip",
    "dest_ip": "destination_ip",
    "hostname": "host",
    "computer": "host",
    "machine": "host",
    "dport": "port",
    "dest_port": "port",
    "destination_port": "port",
    "proto": "protocol",
    "type": "event_type",
    "eventtype": "event_type",
    "category": "event_type",
    "act": "action",
    "result": "status",
    "outcome": "status",
    "sev": "severity",
    "level": "severity",
    "priority": "severity",
    "proc": "process",
    "process_name": "process",
    "image": "process",
    "cmd": "command",
    "commandline": "command",
    "command_line": "command",
    "bytes_out": "bytes",
    "bytes_sent": "bytes",
    "size": "bytes",
    "auth_result": "authentication_result",
    "authresult": "authentication_result",
    "logon_result": "authentication_result",
    # --- CIC-IDS2017 / CSE-CIC-IDS2018 (CICFlowMeter) columns ---
    "dst_port": "port",
    "destination_port": "port",
    "totlen_fwd_pkts": "bytes",
    "total_length_of_fwd_packets": "bytes",
    "flow_bytes_s": "bytes",
    "flow_byts/s": "bytes",
    "label": "label",
}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def new_incident_id() -> str:
    year = _dt.datetime.now().year
    return f"INC-{year}-{uuid.uuid4().hex[:6].upper()}"


def new_response_id() -> str:
    return f"RSP-{uuid.uuid4().hex[:8].upper()}"


def new_experience_id() -> str:
    return f"EXP-{uuid.uuid4().hex[:8].upper()}"


def new_batch_id() -> str:
    return f"BATCH-{uuid.uuid4().hex[:8].upper()}"


def new_assessment_id() -> str:
    return f"ASSESS-{uuid.uuid4().hex[:8].upper()}"


def new_finding_id() -> str:
    return f"FND-{uuid.uuid4().hex[:8].upper()}"


def empty_event() -> dict:
    return {f: None for f in EVENT_FIELDS}
