# Soundness Analysis (2026-02-18)

This report reassesses project and technology soundness after the latest
readiness upgrades (deterministic test profile, CI automation, benchmark
pipeline scaffolding).

## Scope

Evaluated:

- repository maturity and engineering controls
- runtime security model soundness
- evidence quality and claim discipline

Sources:

- local implementation and test artifacts
- OpenClaw official security and hardening docs
- NVD / advisory data for cited incidents
- MCP security best-practice specification
- recent runtime security research (2025-2026)

## Current Scores

### Project readiness soundness: 6.5 / 10

Strengths:

- deterministic profile and toolchain verification in place
- tiered test runner with machine-readable artifacts
- CI pipeline includes fully automated benchmark integrity checks
- security scope and evidence policy now explicit

Gaps:

- hosted CI does not yet execute VM-backed integration suites
- no public release process/versioned changelog yet
- no external security assessment yet

### Technology soundness (architecture): 7.5 / 10

Strengths:

- anomaly-plus-context model aligns with current agent-runtime defense research
- explicit latency-aware settling windows reduce naive stale-data decisions
- rollback-aware action model improves operational safety

Gaps:

- efficacy metrics exist for a trace-backed live protocol, but scenario breadth remains limited
- intent declaration still relies on reasoning-plane integrity assumptions
- model does not yet provide formal guarantees across all attack classes

### Evidence soundness: 6.0 / 10

Strengths:

- claim/evidence mapping exists and is actively updated
- deterministic execution artifacts available:
  - `artifacts/test-summary-full.json`
  - `artifacts/ci-benchmark-summary.json`

Gaps:

- `ci-benchmark-summary.json` validates pipeline correctness, not security efficacy
- trace-backed live precision/recall/latency metrics exist for a narrow protocol; broader scenario coverage still pending
- no independent validation (L4) evidence yet

## What Changed Since Prior Review

1. **Reproducibility hardened**
   - known-good profile and toolchain floors implemented
2. **Automation increased**
   - non-manual CI checks implemented and executed successfully
3. **Validation pipeline created**
   - scenario corpus + NDJSON recorder + metrics summarizer
4. **Claims bounded**
   - evidence matrix now tracks measured vs unmeasured areas

## Residual Risks

| Risk | Likelihood | Impact | Current Mitigation | Next Mitigation |
|---|---|---|---|---|
| Flaky MCP behavior causes skip outcomes in integration checks | Medium | Medium | suite-level pass/skip separation | stabilize MCP check protocol with retries/state reset |
| Over-interpretation of CI synthetic benchmark outputs | Medium | High | explicit CI-integrity caveat in docs | enforce "no efficacy claims without trace-backed live runs" rule in reviews |
| Undetected attack classes outside current scenario set | Medium | High | scenario corpus scaffolded | expand live scenarios and run repeated trace-backed evaluations |
| Missing external assurance | Medium | High | internal templates/processes | third-party review or design-partner validation |

## Conclusion

The project has moved from a pure PoC posture toward a **credible private
preview** with improved engineering and evidence discipline. The most important
remaining step for credibility is broadening the trace-backed live scenario set
and publication of measured efficacy artifacts tied to environment notes and
independent replication.
