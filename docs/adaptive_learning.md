# Adaptive Learning & Response Selection

How the system learns from validated outcomes and uses that knowledge to select
responses — transparently, never as a black box.

## Response selection pipeline

```
Candidate Responses (playbook per attack type)
        ↓
Historical Success        ← measured from verified response_outcomes
        ↓
Memory Trust              ← trust_score of the trusted experience
        ↓
Current Detection Confidence  ← this incident's agent confidence
        ↓
Agent Consensus           ← agreement across the analysis agents
        ↓
Response Risk             ← low / medium / high
        ↓
Rollback Availability     ← reversible action or not
        ↓
Transparent weighted score → highest-scoring candidate recommended
```

## The score (documented, no hard-coded result)

Each candidate gets `recommendation_confidence = Σ weightᵢ · componentᵢ`
(`backend/agents/response_planner.py`, `SCORE_WEIGHTS`):

| Component | Weight | Source (real value) |
|-----------|--------|---------------------|
| historical_success | 0.25 | `memory_agent.strategy_stats(attack_type)` success rate |
| memory_trust | 0.15 | trusted experience `trust_score` |
| current_confidence | 0.20 | incident/agent confidence |
| agent_agreement | 0.15 | consensus agreement |
| response_risk | 0.15 | low=1.0 / medium=0.6 / high=0.3 |
| rollback | 0.10 | 1.0 if reversible else 0.3 |

When there is no validated history, `historical_success` and `memory_trust`
default to **0.5** (neutral) — the system does not pretend to have evidence it
lacks. The recommended candidate is the highest score, ties broken by lower
response risk. The components are returned to the UI and rendered in the
candidate card and the **"Why this decision?"** panel.

## Learning loop

1. A response is approved (or auto-eligible) and **simulated** — no real system
   is touched, and the original events are never modified.
2. **Attack-specific verification** (`backend/verification.py`) recomputes the
   threat indicators after applying the response's coverage predicate and yields
   `VERIFIED_RESOLVED` / `PARTIALLY_RESOLVED` / `THREAT_PERSISTS`.
3. `memory_agent.record_experience(...)` updates the strategy's learned
   confidence with an EWMA (`LEARN_ALPHA=0.4`): **up** on SUCCESS, **down** on
   THREAT_PERSISTS. Only validated outcomes feed learning.
4. Next time a similar incident occurs, `strategy_stats` reflects the new success
   rate and the candidate score rises/falls accordingly.

## Trusted memory (safety)

Experiences are `trusted` / `under_review` / `revoked`. **Revoked experiences
never influence recommendations** (`recommend_strategy` and `strategy_stats`
filter them). Each experience keeps `source_incident`/`provenance`,
`verification_status`, `confidence`, `trust_score`, `created_at`. Proven by
`tests/test_pipeline.py::test_revoked_memory_not_recommended` and
`tests/test_verification.py::test_validated_history_raises_candidate_score`.

## Why it is not a black box

- Every score component is a real, inspectable number.
- The recommendation confidence is a documented weighted sum.
- The "Why this decision?" panel restates the factors and the plain-language
  reason (evidence, agreement, risk, rollback, autonomy, approval requirement).
- Learning only moves confidence in response to **verified** outcomes.
