# ArXiv Readiness Scorecard

- Generated at: 2026-03-09T09:45:58Z
- Verdict: **NO_GO**
- Source: live (0 runs, 0 seeds)
- Passed: 5/14

| Criterion | Severity | Threshold | Observed | Status |
|---|---|---|---|---|
| Benchmark mode is live (trace-backed, not synthetic) | high | `== live` | `live` | PASS |
| Manifest includes git SHA and scenario-set hash | high | `git_sha != unknown AND scenario_set_version != unknown` | `{"git_sha":"473465c","scenario_set_version":"22cb4a6cbddf88154435207c279143f7245de94dbc47c5803ca349eb10f3de1d"}` | PASS |
| Manifest benchmark_mode is explicit (not unknown) | high | `!= unknown` | `live` | PASS |
| Summary has no unknown benchmark_mode rows | high | `== 0` | `0` | PASS |
| Summary total_runs matches manifest valid_runs | high | `summary.total_runs == manifest.counts.valid_runs` | `{"summary_total_runs":0,"manifest_valid_runs":0}` | PASS |
| At least 100 total measured runs | high | `>= 100` | `0` | FAIL |
| Precision CI95 lower bound >= 0.85 | high | `>= 0.85` | `null` | FAIL |
| Recall CI95 lower bound >= 0.85 | high | `>= 0.85` | `null` | FAIL |
| At least 10 distinct seeds | medium | `>= 10` | `0` | FAIL |
| Skipped-run ratio <= 15% | high | `<= 0.15` | `{"skipped_runs":400,"planned_runs":400,"skipped_ratio":1}` | FAIL |
| Scenario coverage ratio >= 80% | high | `>= 0.80` | `{"covered_scenarios":0,"scenario_count":50,"coverage_ratio":0}` | FAIL |
| Scenario-group coverage ratio >= 70% | medium | `>= 0.70` | `{"covered_groups":0,"group_count":30,"coverage_ratio":0}` | FAIL |
| At least 5 evaluated categories | high | `>= 5` | `0` | FAIL |
| Recall stddev across seeds <= 0.15 | high | `<= 0.15` | `null` | FAIL |

