# Adaptive AI Cyber Defense System

**Intelligent Threat Detection, Investigation, and Automated Response — an AI-assisted SOC prototype.**

> Research / industry demonstration prototype. This is an **AI-assisted, adaptive**
> Security Operations Center platform — *not* a production enterprise SOC, and it
> makes no claim of full autonomy, zero false positives, or 100% accuracy.
> Responses are **simulated by default** and no real systems are ever touched.

---

## 1. Overview

This project is an end-to-end, functioning SOC platform that:

1. **Ingests** real security event data (CSV / JSON / syslog) and normalizes it.
2. **Detects** threats using rule-based logic **and** ML/statistical anomaly detection.
3. **Creates incidents** by correlating related events (not one-per-event).
4. Runs a **multi-agent investigation** (detection, investigation, threat-intel,
   correlation, risk, memory) with an **evidence graph** and **MITRE ATT&CK** mapping.
5. Computes an **explainable risk score** and an **agent consensus**.
6. Plans a **response**, **validates** it against six safety checks, and makes an
   **adaptive autonomy decision** (observe → recommend → human approval → auto low-risk).
7. **Simulates** the approved response safely and **verifies** whether the threat persists.
8. Learns from **validated** outcomes into a **trusted incident memory**.
9. Records an **append-only audit trail** and surfaces everything in a live
   **dashboard, incident center, investigation view, response center and analytics**.

Real uploaded data (`dataset='real'`) and synthetic **Demo Mode** data
(`dataset='demo'`) are kept strictly separate everywhere.

## 2. Architecture (high level)

```
Logs/Events → Ingestion → Normalization → Threat Detection (Rules + Anomaly)
   → Incident Creation → Multi-Agent SOC (Detection / Investigation / Threat-Intel
   / Correlation / Risk / Memory) → Evidence Correlation → Risk Scoring
   → Response Planner → Response Validator → Autonomy Decision
   → (Human Approval | Safe Simulation) → Verification → Incident Memory
   → Adaptive Improvement → Analytics
```

Details: [`docs/architecture.md`](docs/architecture.md).

## 3. Technology

| Layer     | Choice                                                          |
|-----------|-----------------------------------------------------------------|
| Backend   | Python + FastAPI + uvicorn                                       |
| ML        | scikit-learn (IsolationForest) + numpy statistical fallback     |
| Data      | pandas / numpy                                                  |
| Database  | SQLite (WAL, indexed)                                           |
| Frontend  | Build-free vanilla-JS SPA served by FastAPI + Chart.js          |
| Live      | Server-Sent Events (SSE) + polling                              |

The frontend is intentionally **build-free** (no npm/Vite build step) so it runs
reliably on Windows out of the box and is trivial to demo and grade. Chart.js is
loaded from a CDN and the UI degrades gracefully (tables/data still work) if the
CDN is unreachable.

## 4. Installation

Requires **Python 3.10+** (developed & tested on Python 3.14). No virtual
environment is needed — it uses your existing Python installation.

```bat
python -m pip install --user -r requirements.txt
```

## 5. How to run

**Windows (recommended):**

```bat
run_dashboard.bat
```

**Any platform:**

```bash
python run.py
```

The launcher finds a free port automatically (starting at 8000) and prints:

```
Application running at:  http://127.0.0.1:8000
```

Open that URL in a browser.

## 6. Configuration

Set via environment variables (safe defaults shown). See [`backend/config.py`](backend/config.py).

| Variable                | Default | Meaning                                             |
|-------------------------|---------|-----------------------------------------------------|
| `APP_ENV`               | development | Environment label                               |
| `DATABASE_PATH`         | data/soc.db | SQLite path                                     |
| `DEMO_MODE`             | true    | Enable demo engine                                  |
| `MAX_EVENTS`            | 50000   | Max events ingested per dataset                     |
| `AUTO_RESPONSE_ENABLED` | **false** | Allow (simulated) auto-execution of low-risk actions |
| `RESPONSE_SIMULATION`   | **true**  | Route all responses through the safe simulator    |
| `RISK_THRESHOLD`        | 0.70    | Risk (0..1) considered high                         |
| `AUTONOMY_LEVEL`        | 3       | Max autonomy level the system may use               |

The two bold defaults guarantee the system can never accidentally perform a real
destructive action.

## 7. Using it

- **Upload data** — *Real Data* page → drag-drop a CSV/JSON/syslog, or click
  **Load bundled sample CSV**. You get event counts, time range, users, hosts,
  failed logins, suspicious counts. See [`docs/real_data.md`](docs/real_data.md).
- **Run detection** — creates correlated incidents.
- **Investigate** — open an incident → multi-agent analysis, evidence timeline,
  clickable evidence graph, risk breakdown, consensus, recommended response.
- **Respond** — *Validate*, *Request Human Approval*, then *Simulate*. The system
  verifies the outcome (indicators before/after) and learns from it.
- **Demo Mode** — Start/Pause/Resume/Stop/Reset continuous synthetic scenarios.
  See [`docs/demo.md`](docs/demo.md).
- **Analytics / Audit / Memory** — dashboards, append-only audit trail, and the
  trusted incident-memory store.

Full workflow and acceptance walkthrough below (§11).

## 8. Database schema

Tables: `events`, `incidents`, `evidence`, `agent_assessments`,
`threat_intelligence`, `responses`, `response_validation`, `response_outcomes`,
`memory`, `audit_logs`, `demo_state`. All indexed on the common query keys and
scoped by `dataset`. `audit_logs` is append-only (enforced by DB triggers).
Schema: [`backend/database.py`](backend/database.py).

## 9. API

Key endpoints (full list in [`docs/api.md`](docs/api.md), live docs at `/docs`):

```
GET  /api/dashboard              GET  /api/analytics
POST /api/events/upload          POST /api/detection/run
GET  /api/incidents              GET  /api/incidents/{id}[/evidence|timeline|analysis|graph|responses|audit]
POST /api/incidents/{id}/investigate
POST /api/responses/{id}/validate|approve|simulate
POST /api/demo/start|stop|pause|resume|reset
GET  /api/audit    GET /api/memory    GET /api/search    GET /api/stream (SSE)
GET  /api/export/incident/{id}.md|.json    /api/export/incidents.csv    /api/export/audit.csv
```

## 10. Testing

```bash
python -m pytest tests/ -q
```

26 tests cover ingestion/normalization, detection (brute-force, port-scan,
single-event no-op), incident creation & correlation-dedup, risk, consensus,
response validation/simulation/verification, memory learning + revocation,
security (injection scan, path traversal, append-only audit), dataset
separation, and the full API workflow. Edge cases (empty/malformed uploads,
oversized files, one failed login, disproportionate high-risk action, revoked
memory) are included.

## 11. Full workflow / acceptance walkthrough

1. Open the app → **Real Data** → *Load bundled sample CSV* (85 synthetic events).
2. See the events + upload stats. Click **Run Detection** → incidents created.
3. **Incident Center** → open an incident.
4. See evidence, investigation timeline, agent assessments, consensus, risk
   score & breakdown, MITRE techniques, evidence graph.
5. Get the recommended response → **Validate** → see whether **Human Approval**
   is required → **Request Human Approval** → **Simulate Response**.
6. See verification (indicators before/after) and the **Audit Log**.
7. See the incident reflected in **Analytics**.
8. **Demo Mode** → *Start* → watch continuous incident generation (switch the top
   toggle to *Demo Data*) → *Stop*.
9. Toggle back to *Real Data* → confirm demo and real data are never mixed.

## 12. Security of the AI system

Raw log content is treated as **data, never instructions**. Prompt-injection /
instruction-smuggling text in logs is flagged as a signal but never executed.
Uploads are size-limited, validated, never executed. Memory is trust-scored and
revoked experiences never influence recommendations. See
[`docs/security.md`](docs/security.md).

## 12b. Upgrade highlights (v1.1)

Built on the original pipeline (nothing removed):

- **Data-quality engine** — every upload returns a report (valid/invalid/rejected/
  duplicate/missing-field counts + detected→normalized field map); junk rows are
  rejected; more field aliases (`sourceAddress`, `destinationAddress`, `event_time`, …).
- **8-check response validation** — added *target validity* and *threat-still-active*.
- **All 9 agents visible** — Consensus, Response-Planning, Response-Validation and
  Autonomy agents are now surfaced alongside the 5 analysis agents (they do not
  pollute the consensus math).
- **Verification enrichment** — `verification_status`, `persistence_detected`,
  confidence.
- **Adaptive learning surfaced** — `/api/memory/strategies` shows measured per-
  strategy success rates; the Memory page renders them; proof-tests show a
  validated success/failure changing future confidence.
- **Analytics upgrade** — avg risk/confidence, autonomous-decision rate, escalation
  rate, memory-reuse rate, detection-method distribution, and a
  **measured/estimated/simulated** honesty legend.
- **Threat-intel enrichment** — `first_seen`/`last_seen`/`confidence`/
  `risk_contribution`, explicit "Local intelligence only".
- **Reports** — added a *Lessons Learned* section.
- **Tests** — 37 total (added 11 proof-tests for Phase-30 claims).
- Docs added: [`docs/evaluation.md`](docs/evaluation.md),
  [`docs/industry_workflow.md`](docs/industry_workflow.md).

## 12c. Upgrade highlights (v1.2)

- **Immutable forensic evidence** — the response simulator no longer edits the
  `events` table. Simulated effects are recorded separately in a new
  `response_effects` table as a *coverage predicate*; original events are never
  mutated (proved by `test_simulation_does_not_mutate_original_events`).
- **Attack-specific verification** (`backend/verification.py`) — verification
  indicators depend on the attack type (auth failures, scan connections,
  outbound bytes, privileged activity, remote logons, malware/process, …); the
  "after" state is computed by applying the response predicate to the unchanged
  events. Returns `verification_status`, per-indicator before/after,
  `persistence_detected`, method and confidence.
- **Transparent adaptive response selection** — every candidate is scored from
  real values (historical success, memory trust, confidence, agreement, response
  risk, rollback); the UI shows the components and a **"Why this decision?"**
  panel. See [`docs/adaptive_learning.md`](docs/adaptive_learning.md).
- **Attack-chain visualization** — ordered stages built only from supporting
  events (`/api/incidents/{id}/chain`), clickable to the underlying events.
- **Anomaly explanation** — model score (IsolationForest) is reported separately
  from the *explanatory heuristics* (rare IP, unusual port, off-hours, failure
  rate, …); stored as incident evidence.
- **Syslog timestamp warning fixed** — RFC3164 dates are parsed with an explicit
  year (no deprecation warning, no timezone shift).
- **Tests** — 46 total (added `tests/test_verification.py`).

## 12d. Upgrade highlights (v1.3)

- **Security Posture Assessment** (flagship) — evidence-based, transparent 0–100
  posture score across 9 categories with **NOT ASSESSED** for missing data,
  coverage reporting, findings + recommendations, history + diff. Never
  fabricates ports/CVEs/reputation. See [`docs/security_assessment.md`](docs/security_assessment.md).
- **Real CIC-IDS dataset ingestion** — CICFlowMeter columns (CIC-IDS2017 /
  CSE-CIC-IDS2018) map into the normalized schema; ground-truth `Label` is stored
  (used only for evaluation). Configurable `DATASET_DIR`. See
  [`data/datasets/README.md`](data/datasets/README.md).
- **Evaluation** — precision / recall / F1 / FPR computed from the dataset's own
  labels (baseline rules-only vs proposed pipeline), with measured timings; shows
  **"Not available"** when no labelled data is loaded (no invented numbers).
- **Deployment-ready** — binds `0.0.0.0`/`$PORT` in production, relative frontend
  URLs, `.env.example`, `render.yaml`, `Procfile`, CORS from env, `/health`.
  See [`docs/deployment.md`](docs/deployment.md).
- **Tests** — 70 total (added assessment, evaluation, and deployment suites).

## 12e. Real datasets (setup)

1. Download **CSE-CIC-IDS2018** (primary) and/or **CIC-IDS2017** (validation)
   from the CIC/UNB dataset pages (see `data/datasets/README.md`).
2. Place the CSV(s) in `data/datasets/` (or set `DATASET_DIR`).
3. In the app → **Real Data** → upload the CSV → **Run Detection**.
4. Open **Security Assessment** (posture) and **Evaluation** (metrics vs labels).

No synthetic data is used for real evaluation; Demo Mode is separate and clearly
labelled, and never leaks into real-data analytics or assessments.

## 13. Limitations

- Detection thresholds and the risk formula are heuristic and tuned for
  demonstration, not production accuracy.
- Threat intelligence uses a **local sample** dataset; external CTI
  (VirusTotal / AbuseIPDB / OTX / MISP) is **not configured** and never fabricated.
- Response execution is **always simulated**; there are no real enforcement
  integrations in this build.
- "False positive rate" is an estimated proxy, not a validated metric.

## 14. Future work

- Pluggable external CTI connectors behind explicit config.
- Streaming ingestion (Kafka / syslog listener) and larger-scale storage.
- Learned detection models per environment; feedback-driven threshold tuning.
- Real (guarded) response integrations behind approval + change control.
- Role-based access control and multi-tenant separation.

---

*Built as an M.Tech industry-oriented project. AI-assisted · adaptive · prototype.*
