# Demo Mode

Demo Mode continuously generates **synthetic, clearly-labelled** attack scenarios
so every page of the platform can be demonstrated without any real data.

> All demo events are stored with `dataset='demo'` and are **never** mixed with
> real uploaded data. Demo data is synthetic and is never presented as real
> company security data. A "DEMO DATA" banner is shown while the demo dataset is
> selected.

## Scenarios

| Scenario | What it generates | Detectors it exercises |
|----------|-------------------|------------------------|
| Brute Force | many failed logins from one IP | `brute_force` |
| Credential Compromise | failed logins → success → privileged command | `credential_compromise` |
| Port Scan | many distinct ports from one IP | `port_scan` |
| Malware Execution | mimikatz + obfuscated PowerShell | `malware_execution`, `suspicious_powershell` |
| Data Exfiltration | large outbound transfers to a malicious IP | `data_exfiltration` |
| Lateral Movement | one user authenticating across many hosts | `lateral_movement` |

## Controls

- **Start** — begins the background engine; a new scenario is emitted every
  `DEMO_TICK_SECONDS` (default 3s), stored, detected, and auto-investigated.
- **Pause / Resume** — halt / continue generation without clearing data.
- **Stop** — stop generation.
- **Reset** — stop and clear **all demo data** (real data is untouched).

The engine auto-pauses at `DEMO_MAX_INCIDENTS` (default 200). It runs as an
asyncio background task and is fully isolated from the request path; any error is
logged to the audit trail and never crashes the app.

## Watching it live

Switch the top toggle to **Demo Data**. The Dashboard, Incident Center,
Investigation, Evidence Graph, Risk, Response Center, Audit Log and Analytics all
read from the same demo state and update live via SSE.

Because `AUTO_RESPONSE_ENABLED=false` by default, demo incidents that warrant a
high-impact action wait for **human approval** — open one and drive the
Validate → Approve → Simulate flow to see verification and learning.

## Programmatic single step

```bash
curl -X POST http://127.0.0.1:8000/api/demo/step \
  -H 'Content-Type: application/json' -d '{"scenario":"port_scan"}'
```
