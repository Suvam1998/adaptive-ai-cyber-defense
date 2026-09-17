# Real Data Ingestion

The **Analyze Real Data** page ingests your own security event data. It is stored
with `dataset='real'` and kept separate from demo data.

## Supported formats

- **CSV** — header row + rows. Columns are mapped to the normalized schema via
  aliases (e.g. `src_ip`, `srcip`, `client_ip` → `source_ip`).
- **JSON** — a top-level array, `{ "events": [...] }`, or NDJSON (one object/line).
- **Syslog / key=value** — RFC3164-ish lines and `key=value` pairs.

Max upload size: `MAX_UPLOAD_BYTES` (default 25 MB). Files are validated, never
executed, and their content is treated strictly as data.

## Normalized event schema

```
timestamp, event_id, source, host, user, source_ip, destination_ip, port,
protocol, event_type, action, status, severity, process, command, bytes,
authentication_result, raw_event
```

Unmapped columns are preserved inside `raw_event`. Timestamps accept ISO-8601,
epoch seconds/millis, and several common formats; unknown values fall back to a
sortable string.

## After upload

You get a summary: total events, time range, event-type histogram, unique
users/hosts, source/destination IP counts, failed logins, suspicious events, and
prompt-injection flags found in log payloads.

## Workflow

1. Upload (or **Load bundled sample CSV** — 85 synthetic events covering brute
   force→compromise, port scan, PowerShell, and exfiltration).
2. Preview normalized events.
3. **Run Detection** → correlated incidents are created.
4. Open an incident → investigate → risk → consensus → response → validate →
   approve → **simulate** → verify → analytics.

## Field mapping tips

If detection under-fires, ensure your data provides:
- `source_ip` and a failure indicator (`status=failure` or
  `authentication_result=failure`) for brute force,
- `port` values for port scans,
- `process` / `command` for PowerShell / malware,
- `bytes` and `destination_ip` for exfiltration.

## Generating the bundled sample

```bash
python data/make_samples.py   # writes data/sample_events.csv and .json
```
