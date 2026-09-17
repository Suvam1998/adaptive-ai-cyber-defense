# Security of the AI System

The defensive system must itself be defensible. Safeguards implemented:

## 1. Logs are DATA, never instructions
Nothing read from an event, upload, or memory is executed or interpreted as a
command to the system. There is no code path that evals/execs log content.

## 2. Prompt-injection / instruction smuggling
`security.scan_injection` flags instruction-like text embedded in log fields
(`ignore previous instructions`, `<system>`, `os.system`, `drop table`, …). When
found, it is recorded as an **evidence signal** on the incident and shown in the
Investigation Agent's rationale — but it never alters system behaviour.

## 3. Malicious event payloads / display safety
`security.sanitize_text` strips control characters and caps length before any log
content is stored or rendered, preventing terminal/DOM corruption. The frontend
additionally HTML-escapes all rendered values.

## 4. Upload safety
- Size-limited (`MAX_UPLOAD_BYTES`, default 25 MB) → `413` if exceeded.
- Parsed and validated; malformed input returns `400`, never a crash.
- Never executed; filenames sanitized (`safe_filename`) to block path traversal.

## 5. Poisoned / untrusted memory
Every learned experience carries `confidence`, `trust_score`,
`validation_status` (trusted / under_review / revoked), `source`, and
`provenance`. **Revoked experiences never influence recommendations.** Learning
happens **only from validated response outcomes** (after verification), never
blindly from every incident.

## 6. Unauthorized / unsafe response execution
- `RESPONSE_SIMULATION=true` (default): all responses are simulated; no real
  systems are touched.
- `AUTO_RESPONSE_ENABLED=false` (default): auto-execution is disabled; any
  autonomy level ≥3 falls back to human approval.
- The Response Validator rejects disproportionate/high-impact actions, and
  rejected responses can never be simulated or approved.
- Significant agent disagreement forces human review.

## 6b. Immutable forensic evidence
The response simulator **never modifies the original `events`**. A simulated
response is stored as a *coverage predicate* in `response_effects` (e.g. "block
source IP X would neutralise these event ids"), and verification recomputes
indicators over the unchanged events. This preserves the forensic record and is
enforced by `tests/test_verification.py::test_simulation_does_not_mutate_original_events`.

## 7. Audit integrity
`audit_logs` is append-only: DB triggers (`audit_no_update`, `audit_no_delete`)
raise on any UPDATE/DELETE, and the application exposes no mutation helpers.

## 8. Secrets / external services
No secrets are committed. External CTI providers are **not** called unless
configured via environment variables; when absent the UI states "External threat
intelligence not configured" rather than fabricating results.

## Threat model notes / non-goals
This is a prototype: there is no authentication/RBAC on the API (intended for
local single-analyst demonstration), and transport is plain HTTP on localhost.
For any shared deployment, add authentication, TLS, and network controls in front
of the app.
