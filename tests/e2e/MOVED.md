# Moved to edamame_posture

The CI-gating parts of this directory now live in `edamame_posture`, which owns
attack-pattern detection and divergence detection end to end. `agent_security`
keeps only the paper pipeline (`tests/benchmark/`) and the operator demos below.

| Was here | Now lives in |
|---|---|
| `tests/e2e/triggers/` (17 trigger scripts) | `edamame_posture/tests/security/triggers/` |
| `tests/e2e/run_fleet_monitoring.py` | `edamame_posture/tests/e2e/run_fleet_monitoring.py` |
| `tests/e2e/supported_agents.py` | `edamame_posture/tests/e2e/supported_agents.py` |
| `tests/e2e/E2E_TESTS.md` | `edamame_posture/tests/e2e/E2E_TESTS.md` |
| `.github/workflows/agent_monitoring_e2e.yml` | `edamame_posture/.github/workflows/agent_monitoring_e2e.yml` |
| `supported_agents/` (registry) | `edamame_foundation/supported_agents/` (mirror kept here for one release cycle) |

`edamame_posture/.github/workflows/agent_monitoring_e2e.yml` is the sole agent
E2E release gate (`edamame_app/release_all.sh`, `AGENT_PLUGIN_E2E_WORKFLOWS`).
The CVE corpus is consumed by the `security` job in
`edamame_posture/.github/workflows/tests.yml`, which stages the vendored
triggers from the repo instead of fetching them over HTTP.

## What is still here

`run_demo.sh`, `run_e2e_harness.sh`, `DEMO.md`, and `demos/` are operator and
video-capture tooling, not release gates. They resolve the trigger corpus and
`supported_agents.py` from the sibling `edamame_posture` clone (override with
`EDAMAME_POSTURE_REPO`), or from a local `tests/e2e/triggers/` copy if one is
staged.
