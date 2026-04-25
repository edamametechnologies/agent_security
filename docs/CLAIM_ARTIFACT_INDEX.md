# Claim-to-Artifact Index

This file is the canonical mapping between public metric claims and the exact
artifact lineage that supports them.

## Canonical Evidence Set

- Summary: `artifacts/live-paper-summary.json`
- Manifest: `artifacts/live-paper-manifest.json`
- Raw runs: `artifacts/live-paper-results.ndjson`
- Readiness scorecard: `artifacts/readiness-scorecard.json`

Current committed manifest binding:

- `run_id`: `run-live-20260313T194140Z-live`
- `git_sha`: `aca9156`
- `scenario_set_version`: `fa1266a7eb7b2645ecad1b31258ea661710f47bd1cba01ffef5817536a04b4aa`
- `mode`: `live`
- `benchmark_mode`: `live` (all runs use live trace-backed skill-native reasoning)

## Claim Mapping

| Claim ID | Public claim type | Exact artifact fields | Artifact files |
|---|---|---|---|
| `CLM-001` | Sample size | `.total_runs` | `artifacts/live-paper-summary.json` |
| `CLM-002` | Precision + CI95 | `.precision`, `.precision_ci95.low`, `.precision_ci95.high` | `artifacts/live-paper-summary.json` |
| `CLM-003` | Recall + CI95 | `.recall`, `.recall_ci95.low`, `.recall_ci95.high` | `artifacts/live-paper-summary.json` |
| `CLM-004` | Detection latency | `.median_latency_ms`, `.p95_latency_ms`, `.TTD.*` (if present) | `artifacts/live-paper-summary.json` |
| `CLM-005` | Rollback reliability | `.rollback_reliability`, `.rollback.attempts`, `.rollback.success`, `.rollback.failure` | `artifacts/live-paper-summary.json` |
| `CLM-006` | Run mode and scenario binding | `.mode`, `.benchmark_mode`, `.run_id`, `.git_sha`, `.scenario_set_version`, `.scenario_count`, `.group_count` | `artifacts/live-paper-manifest.json` |
| `CLM-007` | Skip/diversity gate outcomes | `.criteria[]` entries for `skip_ratio`, `scenario_coverage`, `group_coverage`, `category_diversity` | `artifacts/readiness-scorecard.json` |

## Verification Commands

```bash
jq '{total_runs, precision, recall, precision_ci95, recall_ci95, median_latency_ms, p95_latency_ms, rollback_reliability, rollback}' artifacts/live-paper-summary.json
jq '{run_id, mode, benchmark_mode, git_sha, scenario_set_version, scenario_count, group_count, counts}' artifacts/live-paper-manifest.json
jq '{verdict, criteria}' artifacts/readiness-scorecard.json
shasum -a 256 artifacts/live-paper-summary.json artifacts/live-paper-manifest.json artifacts/live-paper-results.ndjson
```

## Publication Rule

Any public metric statement in `README.md`, `paper/whitepaper_draft.md`, or external
communications must cite this index and include:

1. `run_id`
2. `git_sha`
3. `scenario_set_version`
4. `mode` and `benchmark_mode`
5. exact source fields listed in the claim mapping table
