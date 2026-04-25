# Publication Readiness Scorecard

- Generated at: 2026-02-23T03:13:47Z
- Verdict: **CONDITIONAL_GO**
- Source: live (100 runs, 25 seeds)
- Passed: 10/11

| Criterion | Severity | Threshold | Observed | Status |
|---|---|---|---|---|
| Benchmark mode is live (trace-backed, not synthetic) | high | `== live` | `live` | PASS |
| Manifest includes git SHA and scenario-set hash | high | `git_sha != unknown AND scenario_set_version != unknown` | `{"git_sha":"fcd3731","scenario_set_version":"8632b58c5058976eb21e3f44733c5adb79a9862fcb381f0df395a79f28bcf0d4"}` | PASS |
| At least 100 total measured runs | high | `>= 100` | `100` | PASS |
| Precision CI95 lower bound >= 0.85 | high | `>= 0.85` | `0.9286499658256813` | PASS |
| Recall CI95 lower bound >= 0.85 | high | `>= 0.85` | `0.9286499658256813` | PASS |
| At least 10 distinct seeds | medium | `>= 10` | `25` | PASS |
| Skipped-run ratio <= 15% | high | `<= 0.15` | `{"skipped_runs":0,"planned_runs":100,"skipped_ratio":0}` | PASS |
| Scenario coverage ratio >= 80% | high | `>= 0.80` | `{"covered_scenarios":4,"scenario_count":4,"coverage_ratio":1}` | PASS |
| Scenario-group coverage ratio >= 70% | medium | `>= 0.70` | `{"covered_groups":2,"group_count":2,"coverage_ratio":1}` | PASS |
| At least 5 evaluated categories | medium | `>= 5` | `1` | FAIL |
| Recall stddev across seeds <= 0.15 | high | `<= 0.15` | `0` | PASS |

