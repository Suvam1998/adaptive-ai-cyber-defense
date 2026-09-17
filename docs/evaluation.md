# Evaluation Methodology

This document explains **how the system's outputs should be interpreted** and how
an evaluator can reproduce and judge them. It is deliberately conservative: the
project is an AI-assisted prototype, and metrics are labelled by how trustworthy
they are.

## 1. Metric honesty labels

Every dashboard/analytics metric is tagged in the API response under
`metric_types` as one of:

| Label | Meaning | Examples |
|-------|---------|----------|
| **Measured** | Counted directly from stored records | incidents, responses executed, response success rate, autonomous-decision rate, detection-method distribution |
| **Estimated** | Heuristic proxy, not ground truth | average risk, average confidence, memory-reuse rate, false-positive rate, timing |
| **Simulated** | Produced by the safe simulator, not real enforcement | response execution results |

Do **not** read "Estimated" numbers as validated accuracy figures.

## 2. What is genuinely functional (not faked)

| Capability | Evidence it is real |
|------------|---------------------|
| Detection | `tests/test_pipeline.py` (brute force, port scan, single-event no-op) |
| Correlation dedup | `test_correlation_does_not_duplicate_incident` |
| Risk score | computed from a documented weighted formula; breakdown returned |
| Consensus / disagreement | `test_agent_disagreement_increases_escalation` |
| 8-check validation | `test_validation_has_eight_checks`, `test_invalid_target_is_rejected` |
| Safe simulation + verification | `test_full_response_flow_and_learning`, before/after indicator counts |
| Adaptive learning | `test_learning_influences_future_recommendation`, `test_failed_verification_reduces_strategy_confidence` |
| Trusted memory / revocation | `test_revoked_memory_not_recommended` |
| Dataset isolation | `test_demo_data_never_in_real_and_vice_versa` |
| Log-injection safety | `test_injection_scan_flags_but_does_not_execute` |
| Append-only audit | `test_audit_append_only` |

Run all of it:

```bash
python -m pytest tests/ -q      # 37 tests
```

## 3. Reproducible evaluation run

1. `python run.py` → open the printed URL.
2. **Real Data → Load bundled sample CSV** → data-quality report appears
   (total / valid / rejected / duplicates / field normalization).
3. **Run Detection** → several correlated incidents.
4. Open the credential-compromise incident → verify:
   - 9 agent assessments shown (5 analysis + consensus/plan/validation/autonomy),
   - risk breakdown sums to the displayed total,
   - 8 validation checks listed,
   - evidence timeline ordered chronologically,
   - evidence-graph nodes clickable → underlying events.
5. **Request Human Approval → Simulate** → verification shows indicators
   before → after and `VERIFIED_RESOLVED`.
6. **Incident Memory** → the strategy now shows a measured success rate; the next
   similar incident's Response Planner prefers it.
7. **Analytics** → detection-method distribution and the measured/estimated/
   simulated legend.

## 4. Suggested evaluation criteria (M.Tech)

| Dimension | How to assess |
|-----------|---------------|
| Correctness | Do detections fire only with evidence? Are conclusions grounded? |
| Explainability | Can you trace every risk point and every agent verdict to evidence? |
| Safety | Confirm `AUTO_RESPONSE_ENABLED=false`, high-risk actions need approval, logs never execute |
| Adaptivity | Show a validated success changing a future recommendation |
| Engineering | Tests pass, no tracebacks to UI, dataset isolation holds |

## 5. Known measurement limitations

- No labelled ground-truth dataset ⇒ precision/recall are not reported (only a
  heuristic false-positive proxy).
- Timing metrics reflect wall-clock between DB timestamps at demo scale, not a
  benchmarked SOC SLA.
- Threat intelligence is a local sample; reputation is illustrative.
