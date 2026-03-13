# Credibility Evidence Matrix

This document maps project claims to evidence quality.

Evidence levels:

- **L1**: implemented in code/docs
- **L2**: exercised in local tests
- **L3**: validated with repeatable benchmark metrics
- **L4**: independently validated (third-party audit/research)

Canonical claim-to-artifact binding:

- `docs/CLAIM_ARTIFACT_INDEX.md`

## Current Claim Mapping

| Claim | Scope | Current Evidence | Level | Gaps |
|---|---|---|---|---|
| The repo provides Layer 3 runtime monitoring patterns for OpenClaw | architecture | `docs/ARCHITECTURE.md`, `skill/*/SKILL.md` | L1 | none |
| Skill is installable and runnable in PoC environment | implementation | `skill/*`, `docs/SETUP.md`, `tests/run_tests.sh`, `artifacts/test-summary-full.json` | L2 | multi-host reproducibility evidence |
| Vulnerability-detection checks cover cited incidents (CVE-2026-25253, CVE-2026-24763, VirusTotal-documented skill abuse patterns) | detection logic | `edamame_core/src/agentic/divergence_engine.rs`, `tests/test_vulnerability_detection.sh`, `artifacts/test-summary-full.json` | L2 | attack replay validation |
| Divergence / intent correlation is complemented by vulnerability / safety-floor and advisor / remediation loops | runtime detection model | `docs/ARCHITECTURE.md`, `edamame_core/src/agentic/divergence_engine.rs`, `skill/edamame-extrapolator/SKILL.md` | L1 | broader quantitative detection accuracy beyond current live scenario set |
| Network intent-vs-egress metrics are measured in a trace-backed live suite and claim-gated by canonical artifacts | benchmark metrics | `tests/benchmark/run_live_suite.py`, `tests/benchmark/live-scenarios/`, `tests/benchmark/summarize_results.sh`, `artifacts/live-paper-summary.json`, `docs/CLAIM_ARTIFACT_INDEX.md` | L3 | multi-host replication; comparative baselines |
| Runtime layer complements static scanning and config audit layers | security positioning | OpenClaw docs + local architecture docs | L1 | independent operational evaluation |
| Workflow is safe-by-default for destructive actions | safeguards | manual confirmation mode + undo tooling references | L1 | formal safety test cases |
| CI/CD validates code quality and claim consistency | engineering quality | `.github/workflows/tests.yml` (`quality`/`integration`/`real_lima`/`artifacts` jobs), `tests/ci_pipeline.sh` | L2 | expand real-lima lane history/retention for longitudinal trend analysis |

## Latest Measured Run (Private)

- Date (UTC): 2026-02-18
- Profile: `tests/profiles/known-good.env`
- Toolchain gate: pass (`setup/verify_toolchain.sh`)
- Test runner command:
  - `./tests/run_tests.sh --suite full --artifact artifacts/test-summary-full.json`
- Live benchmark command:
  - `./tests/benchmark/run_live_suite.sh --scenario-dir tests/benchmark/live-scenarios --iterations 25 --seed 50`
- Artifact summary:
  - suites passed: full tier (`smoke` + integration suite)
  - suite failures: 0
  - canonical metric lineage: `docs/CLAIM_ARTIFACT_INDEX.md`
- Notes:
  - one internal sub-check in integration was reported as SKIP due to variable
    MCP response shape; this did not fail suite-level status.
  - Efficacy claims are based exclusively on trace-backed live runs under a
    defined protocol.

## Source Quality Notes

- High-confidence references: OpenClaw official docs/security advisories, NVD
- Medium-confidence references: peer-reviewed or preprint research papers
- Lower-confidence references: vendor blogs/threat feeds without raw datasets

## Required Upgrades for Public Claims

Before moving core claims to L3/L4:

1. expand live scenario coverage (more tools, destinations, benign-but-anomalous negatives)
2. publish precision/recall/latency tradeoffs tied to scenario set version and environment notes
3. measure rollback reliability on reversible action classes (where applicable)
4. add third-party assessment or reproducible external validation

## Claim Editing Rule

Use this wording discipline in user-facing docs:

- "implements" for L1
- "demonstrates in PoC tests" for L2
- "measured" only for L3+
- "independently validated" only for L4
