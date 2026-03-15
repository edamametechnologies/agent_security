# ArXiv Readiness Scorecard

- Generated at: 2026-03-14T17:48:27Z
- Verdict: **GO**
- Source: live (468 runs, 10 seeds)
- Passed: 14/14

| Criterion | Severity | Threshold | Observed | Status |
|---|---|---|---|---|
| Benchmark mode is live (trace-backed, not synthetic) | high | `== live` | `live` | PASS |
| Manifest includes git SHA and scenario-set hash | high | `git_sha != unknown AND scenario_set_version != unknown` | `{"git_sha":"aca9156","scenario_set_version":"fa1266a7eb7b2645ecad1b31258ea661710f47bd1cba01ffef5817536a04b4aa"}` | PASS |
| Manifest benchmark_mode is explicit (not unknown) | high | `!= unknown` | `live` | PASS |
| Summary has no unknown benchmark_mode rows | high | `== 0` | `0` | PASS |
| Summary total_runs matches manifest valid_runs | high | `summary.total_runs == manifest.counts.valid_runs` | `{"summary_total_runs":468,"manifest_valid_runs":468}` | PASS |
| At least 100 total measured runs | high | `>= 100` | `468` | PASS |
| Precision CI95 lower bound >= 0.85 | high | `>= 0.85` | `0.988026490330431` | PASS |
| Recall CI95 lower bound >= 0.85 | high | `>= 0.85` | `0.8763311151407897` | PASS |
| At least 10 distinct seeds | medium | `>= 10` | `10` | PASS |
| Skipped-run ratio <= 15% | high | `<= 0.15` | `{"skipped_runs":32,"planned_runs":500,"skipped_ratio":0.064}` | PASS |
| Scenario coverage ratio >= 80% | high | `>= 0.80` | `{"covered_scenarios":47,"scenario_count":50,"coverage_ratio":0.94}` | PASS |
| Scenario-group coverage ratio >= 70% | medium | `>= 0.70` | `{"covered_groups":27,"group_count":30,"coverage_ratio":0.9}` | PASS |
| At least 5 evaluated categories | high | `>= 5` | `8` | PASS |
| Recall stddev across seeds <= 0.15 | high | `<= 0.15` | `0.009001831155373185` | PASS |

