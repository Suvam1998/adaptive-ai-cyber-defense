# Industry Analyst Workflow

How this prototype maps onto a real-world SOC analyst's day, and the exact
12-step path the tool supports.

## The 12-step Real Data workflow

| # | Step | Where | What actually happens |
|---|------|-------|-----------------------|
| 1 | **Upload data** | Real Data page | CSV/JSON/syslog accepted, size-limited, never executed |
| 2 | **Profile data** | upload summary | Data-quality report: total/valid/rejected/duplicates/missing fields |
| 3 | **Normalize** | ingestion | Field aliases → canonical schema; unmapped kept in `raw_event` |
| 4 | **Run detection** | `POST /api/detection/run` | Rules + IsolationForest anomaly detection |
| 5 | **Create incidents** | orchestrator | Correlated by IP/user/host/type/time — not one-per-event |
| 6 | **Investigate** | Investigation page | 5 analysis agents build timeline, entities, hypothesis |
| 7 | **Assess risk** | Risk Agent | Explainable 5-component score /100 |
| 8 | **Plan response** | Response Planner | Multiple candidate playbook actions, memory-informed |
| 9 | **Validate** | Response Validator | 8 safety checks → APPROVED / NEEDS_APPROVAL / REJECTED |
| 10 | **Approve / simulate** | Autonomy + simulator | High-risk needs human approval; simulation only |
| 11 | **Verify** | Verifier | Indicators before/after → SUCCESS / PARTIAL / THREAT_PERSISTS |
| 12 | **Learn** | Memory Agent | Validated outcome updates strategy confidence for future incidents |

Each step writes to the **append-only audit log**, so the whole investigation is
traceable end-to-end.

## Mapping to SOC roles

| SOC concept | This system |
|-------------|-------------|
| SIEM ingestion / normalization | `ingestion.py` + normalized schema |
| Detection rules / UEBA | `detection/rules.py` + `detection/anomaly.py` |
| Alert triage / correlation | orchestrator incident creation |
| Tier-1/2 investigation | multi-agent investigation + evidence graph |
| Threat intel enrichment | `threat_intel_agent` (local sample; pluggable) |
| Risk-based prioritization | `risk_agent` explainable score |
| SOAR playbooks | `response_planner` + `response_exec` (simulated) |
| Change control / approval | autonomy levels + human approval gate |
| Post-incident review | reports + Lessons Learned + incident memory |
| Continuous improvement | adaptive learning from verified outcomes |

## Autonomy governance (why it is safe for industry demo)

- `AUTO_RESPONSE_ENABLED=false` and `RESPONSE_SIMULATION=true` by default.
- Any computed autonomy level ≥3 is downgraded to human approval unless auto is
  explicitly enabled.
- High/medium-risk actions (isolate host, disable account) always require human
  approval; the validator rejects disproportionate actions outright.
- Real enforcement integrations are intentionally absent; they would sit behind
  explicit configuration + approval + change control.

## Where real integrations would attach later

| Extension point | Interface today |
|-----------------|-----------------|
| External CTI (VirusTotal/AbuseIPDB/OTX/MISP) | `threat_intel_agent.lookup` (returns "Local intelligence only" until configured) |
| Real response actuation (firewall/EDR/IdP) | `response_exec.simulate` → replace with guarded connector |
| Streaming ingestion | `ingestion.ingest` (batch today; add a syslog/Kafka listener) |
| Case management / ticketing | `reports.py` export (MD/JSON/CSV) |
