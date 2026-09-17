# Security Posture Assessment

Answers: *"What is the current security posture of this authorized environment,
based on the evidence actually available?"* — using only data present in the
selected dataset, never fabricated ports, services, CVEs, or reputation.

## Workflow

```
Authorized system / real dataset
        ↓  (events + incidents already in the DB)
Security checks (9 categories)
        ↓
Evidence collection (event ids / observed values)
        ↓
Transparent per-category scoring (visible deductions)
        ↓
Security Posture Score + Coverage
        ↓
Findings  →  Recommendations
        ↓
Stored to history  →  Reassessment / diff
```

## Categories (9)

| Category | Evidence used | If no evidence |
|----------|---------------|----------------|
| Network Exposure | observed ports, suspicious ports, port-scan incidents | NOT ASSESSED |
| Authentication Security | failed/success logins, brute-force/credential incidents | NOT ASSESSED |
| Access Control | privileged activity, privilege-escalation incidents | NOT ASSESSED |
| Software / Vulnerability | process/version info (no CVE fabrication) | NOT ASSESSED |
| Security Configuration | security-control fields | NOT ASSESSED |
| Logging & Monitoring | field-coverage of security telemetry | NOT ASSESSED |
| Encryption | cleartext/legacy protocol exposure (ports) | NOT ASSESSED |
| Threat Indicators | local CTI reputation of observed IPs | NOT ASSESSED |
| Incident History | open / high-risk incidents in the dataset | NOT ASSESSED |

## Scoring (transparent, reproducible)

- Each category starts at 100 and records **deductions** as
  `{reason, points}` — all visible in the UI ("Why this score?").
- Category status is **ASSESSED / PARTIALLY_ASSESSED / NOT_ASSESSED**.
- **Overall score = mean of the ASSESSED category scores only.** A category with
  no evidence cannot inflate or deflate the overall score — it is excluded, and
  **Coverage (assessed / 9)** is shown prominently. NOT ASSESSED is never treated
  as secure, and a misleading 100/100 under low coverage is impossible.
- If coverage < 50 %, the posture label states *"Low coverage — insufficient
  data for a reliable posture."*

Determinism is guaranteed (no randomness) and covered by
`tests/test_security_assessment.py::test_score_is_deterministic`.

## Findings & recommendations

Each finding carries: `finding_id, category, title, severity, confidence,
affected_asset, evidence[], explanation, recommendation, source, timestamp`.
Every finding references real evidence (proved by
`test_findings_contain_evidence_no_synthetic`). Recommendations are derived from
findings (each carries priority, reason, evidence, expected benefit, and
implementation risk) and never claim to have been implemented.

## Data isolation
Assessments are scoped by `dataset`. The page shows a clear **DEMO** warning when
assessing demo data, and demo assessments never affect real ones. Resetting demo
clears only demo assessments (`test_history_and_dataset_isolation`).

## API
```
GET  /api/security-assessment?dataset=real         # latest + diff
POST /api/security-assessment/run  {dataset}        # run a new assessment
GET  /api/security-assessment/history?dataset=real
GET  /api/security-assessment/{assessment_id}
```

## Tables
`security_assessments` (with transparent `category_scores` JSON),
`security_findings`, `security_recommendations`.
