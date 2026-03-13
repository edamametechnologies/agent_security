# LLM Usage and Governance

This document defines where model inference is used, what is logged, and how
results are validated before being treated as evidence.

## Scope

LLM usage in this repository is limited to runtime and test paths where
natural-language interpretation is required. Deterministic validation and
artifact integrity checks remain the default for claim-bearing workflows.

## Where Inference Is Used

## Runtime Paths

- Extrapolator reasoning plus internal divergence engine correlation over observed telemetry.
- Narrative summarization in final operator-facing reports.

## Test and Benchmark Paths

- `tests/test_attack_detection.sh` (LLM-driven attack interpretation).
- `tests/test_vulnerability_detection.sh` (mixed deterministic + LLM vulnerability-detection checks).
- `tests/benchmark/run_live_suite.py` (live trace-backed benchmark; all runs use
  skill-native reasoning over real EDAMAME telemetry).

## Model Configuration Inputs

Model/provider selection is controlled through environment variables, including:

- `OPENCLAW_MODEL_PROVIDER`
- `OPENAI_PRIMARY_MODEL`
- `OPENAI_API_KEY` (or alternate provider key)

These configuration values must be captured in run artifacts or CI logs for
any claim-bearing run.

## Required Evidence for Claim-Bearing Runs

A run can back public claims only when all items below are present:

1. `artifacts/live-paper-summary.json`
2. `artifacts/live-paper-manifest.json`
3. `artifacts/live-paper-results.ndjson`
4. claim mapping in `docs/CLAIM_ARTIFACT_INDEX.md`

## Human Validation Requirements

Before promoting run outputs to paper/docs claims:

1. Validate summary/manifest schema and hashes.
2. Confirm scenario coverage, skip ratio, and seed coverage thresholds.
3. Verify at least one manual trace review from `artifacts/live-traces/`.
4. Confirm no claim sentence appears without claim-index binding.

## Disclosure Policy for Publications

Any manuscript, blog, or external report using this repository must disclose:

- that LLM-assisted paths exist,
- and which artifact family (run id + git sha + scenario set hash) supports
  each public metric statement.
