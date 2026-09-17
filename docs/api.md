# API Reference

Base URL: `http://127.0.0.1:<port>` (default 8000). Interactive docs at `/docs`.

All list/analytics endpoints take `?dataset=real|demo` (default `real`). Real and
demo data never mix.

## System
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/api/config` | Safe-mode flags, thresholds, autonomy cap |

## Events / ingestion
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/events?dataset=&limit=&offset=` | Paginated event preview |
| POST | `/api/events/upload` | multipart: `file`, `dataset`, optional `fmt`. Returns upload summary |
| GET | `/api/samples` | List bundled sample files |
| POST | `/api/samples/load` | `{name}` — ingest a bundled sample into `real` |
| POST | `/api/detection/run` | `{dataset, batch_id?}` — run detection, create incidents |

Upload summary fields: `count, time_range, event_types, unique_users,
unique_hosts, source_ips, destination_ips, failed_logins, suspicious_events,
injection_flags, batch_id, format, stored, dataset` plus a **`data_quality`**
object: `total_records, valid_records, invalid_records, rejected_records,
missing_timestamps, missing_ip_addresses, missing_users, duplicate_records,
detected_fields, normalized_fields, unmapped_fields`.

## Incidents
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/incidents?dataset=&severity=&status=&attack_type=&host=&user=&min_risk=` | Filterable list |
| GET | `/api/incidents/{id}` | Incident detail |
| GET | `/api/incidents/{id}/evidence` | Evidence rows |
| GET | `/api/incidents/{id}/timeline` | Chronological timeline |
| GET | `/api/incidents/{id}/analysis` | Stored multi-agent analysis (after investigation) — includes `attack_chain`, `decision_explanation`, scored `plans` |
| GET | `/api/incidents/{id}/graph` | Evidence graph (nodes + edges) |
| GET | `/api/incidents/{id}/chain` | Ordered attack chain (evidence-backed stages) |
| GET | `/api/incidents/{id}/effects` | Simulated response effects (separate from immutable events) |
| GET | `/api/incidents/{id}/responses` | Responses for the incident |
| GET | `/api/incidents/{id}/audit` | Audit entries for the incident |
| POST | `/api/incidents/{id}/investigate` | Run/re-run the full investigation |
| POST | `/api/incidents/{id}/response/plan` | (Re)plan responses |

## Responses
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/responses?dataset=` | All responses, bucketed by status |
| POST | `/api/responses/{id}/validate` | Return validation decision + checks |
| POST | `/api/responses/{id}/approve` | Record human approval |
| POST | `/api/responses/{id}/simulate` | Safe-simulate + verify (blocked pre-approval when required) |

## Demo mode
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/demo/state` | Status + counters |
| POST | `/api/demo/start\|pause\|resume\|stop\|reset` | Control the engine |
| POST | `/api/demo/step` | `{scenario}` — generate one scenario immediately |

## Analytics / audit / memory / intel / search
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard?dataset=` | KPI summary |
| GET | `/api/analytics?dataset=` | Summary + chart datasets |
| GET | `/api/audit?dataset=&limit=` | Recent audit entries |
| GET | `/api/memory` | Learned experiences |
| GET | `/api/memory/strategies` | Measured per-strategy success rates (adaptive learning) |
| POST | `/api/memory/{experience_id}/trust` | `{status: trusted\|under_review\|revoked}` |
| GET | `/api/threat-intel/lookup?indicator=&type=` | Local CTI lookup |
| GET | `/api/search?q=&dataset=` | Global search (incident/IP/user/host/technique) |

## Live + export
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stream?dataset=` | SSE: dashboard + demo state every ~2.5s |
| GET | `/api/export/incident/{id}.md` | Markdown incident report |
| GET | `/api/export/incident/{id}.json` | Full incident bundle JSON |
| GET | `/api/export/incidents.csv?dataset=` | Incident CSV |
| GET | `/api/export/audit.csv?dataset=` | Audit CSV |

## Errors
- `400` invalid/empty/malformed upload or bad request
- `404` unknown incident/response/sample
- `413` upload exceeds `MAX_UPLOAD_BYTES`
The dashboard never crashes on API errors; messages are surfaced as toasts.
