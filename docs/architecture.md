# Architecture

## Pipeline

```
        LOGS / EVENTS (CSV / JSON / syslog)
                 |
          Ingestion Layer            backend/ingestion.py
                 |  parse + validate
          Normalization              -> canonical event schema (models.EVENT_FIELDS)
                 |
          Threat Detection           backend/detection/
            /            \
   Anomaly Detection   Rule Detection
   (IsolationForest)   (rules.py)
            \            /
          Incident Creation          agents/orchestrator.py (correlated, deduped)
                 |
          Multi-Agent SOC            backend/agents/
   Detection · Investigation · Threat-Intel · Correlation · Risk · Memory
                 |
          Evidence Correlation       correlation_agent.py (evidence graph)
                 |
          Risk Scoring               risk_agent.py (explainable, /100)
                 |
          Agent Consensus            consensus.py
                 |
          Response Planner           response_planner.py
                 |
          Response Validator         response_validator.py (6 checks)
                 |
          Autonomy Decision          autonomy.py (levels 0..4, governance-capped)
             /        \
      Human Approval   Auto Response (simulated, low-risk only, if enabled)
             \        /
          Safe Simulation            response_exec.py
                 |
          Verification               response_exec.py (indicators before/after)
                 |
          Incident Memory            memory_agent.py (trusted, provenance)
                 |
          Adaptive Improvement       EWMA confidence update from validated outcomes
                 |
          Analytics                  analytics.py
```

## Components / responsibilities

| Module | Responsibility |
|--------|----------------|
| `config.py` | Central, env-overridable configuration; safe defaults |
| `database.py` | SQLite schema, thread-safe access, append-only audit triggers, dataset reset |
| `models.py` | Canonical normalized event schema + id helpers |
| `ingestion.py` | Parse CSV/JSON/syslog → normalize → store → upload summary |
| `security.py` | Sanitization, injection scanning, safe filenames |
| `detection/rules.py` | Deterministic detectors (brute force, port scan, PowerShell, priv-esc, exfil, lateral, malware, suspicious ports) |
| `detection/anomaly.py` | IsolationForest + statistical fallback with explanations |
| `detection/mitre.py` | ATT&CK technique mapping (evidence-gated) |
| `agents/detection_agent.py` | Interprets detection strength |
| `agents/investigation_agent.py` | Timeline + entity gathering + hypothesis |
| `agents/threat_intel_agent.py` | Local CTI reputation lookups (no fabrication) |
| `agents/correlation_agent.py` | Builds the clickable evidence graph |
| `agents/risk_agent.py` | Explainable 5-component risk score |
| `agents/memory_agent.py` | Historical recall, adaptive learning, trusted memory |
| `agents/consensus.py` | Cross-agent agreement / disagreement |
| `agents/response_planner.py` | Candidate response plans (playbooks + memory) |
| `agents/response_validator.py` | 6 safety checks → APPROVED / NEEDS_APPROVAL / REJECTED |
| `agents/autonomy.py` | Risk-aware autonomy level, governance-capped |
| `agents/orchestrator.py` | Drives the whole lifecycle; maintains incident state |
| `response_exec.py` | Safe response **simulation** + verification |
| `analytics.py` | Dashboard + chart aggregations |
| `reports.py` | Markdown / JSON / CSV export |
| `demo.py` | Background synthetic scenario engine (DEMO dataset) |
| `main.py` | FastAPI API + static SPA + SSE |

## Risk scoring formula (documented)

Risk = weighted sum of five components, each capped, total out of 100
(`agents/risk_agent.py`):

| Component | Max | Driven by |
|-----------|-----|-----------|
| Evidence confidence | 30 | detection + agent confidence, correlated event count |
| Asset criticality | 25 | sensitivity (host/user markers) & count of affected assets |
| Threat severity | 20 | detection severity (Critical=1.0 … Low=0.3) |
| Behaviour anomaly | 15 | ML / statistical anomaly score |
| Threat intelligence | 10 | local CTI reputation of involved indicators |

`risk_score` (0..1) used elsewhere = total / 100.

## Autonomy levels

`0` Observe · `1` Recommend · `2` Human approval · `3` Auto low-risk · `4`
Controlled autonomous. The computed level is capped by `AUTONOMY_LEVEL`, and any
level ≥3 still requires `AUTO_RESPONSE_ENABLED=true` (default false) — otherwise
human approval is enforced. Destructive / high-risk actions are never auto-run.

## Response simulation & verification (immutable)

`response_exec.simulate()` records a **coverage predicate** in `response_effects`
— it does not modify `events`. `backend/verification.py` then computes the
"after" state by filtering the unchanged events through that predicate, using
**attack-type-specific indicators**:

| Attack type | Indicators verified |
|-------------|---------------------|
| brute_force | auth failures |
| credential_compromise | auth failures, successful logins, privileged activity |
| port_scan | scan connections, distinct ports |
| malware_execution | malware/offensive-tool indicators |
| suspicious_powershell | suspicious process/script execution |
| privilege_escalation | privileged activity |
| lateral_movement | remote auth events, distinct hosts |
| data_exfiltration | outbound transfers, outbound bytes |
| anomalous_behaviour | anomalous events |

Result: `verification_status` ∈ {VERIFIED_RESOLVED, PARTIALLY_RESOLVED,
THREAT_PERSISTS, INCONCLUSIVE}, per-indicator before/after, `persistence_detected`
and confidence.

## Incident state machine

`New → Investigating → Awaiting Approval → Contained/Closed`
(with `Follow-up` when a verified response shows the threat persists).
