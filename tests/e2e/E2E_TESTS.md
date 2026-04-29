# Agent Security E2E Test Architecture

> **Looking to run a demo?** See [DEMO.md](DEMO.md) for step-by-step
> instructions to reproduce vulnerability and divergence detection demos.

End-to-end test infrastructure for validating EDAMAME's two-plane security
model across the supported agent integration packages declared in
`agent_security/supported_agents/index.json`. The current registry includes
OpenClaw, Cursor, Claude Code, and Claude Desktop.

All E2E tests live in this directory (`agent_security/tests/e2e/`).
Trigger scripts are parameterized with `--agent-type` so one canonical
copy covers all supported agent platforms. The `supported_agents.py` helper
resolves repo paths, validates repo-local lifecycle scripts, and drives the
registry-backed harnesses.

## Two Test Suites

### 1. Intent E2E (`--focus intent`)

Tests the **reasoning-plane** pipeline: synthetic agent transcripts are
injected via `edamame_cli`, processed by the core LLM, and verified by
polling `get_behavioral_model` until predictions appear for every expected
session key.

Each agent platform has its own intent injection script (genuinely
different implementations), living in its respective repo. The automated
harness discovers these entries from the supported-agent registry at runtime:

| Script | Repo | What it does |
|--------|------|--------------|
| `tests/e2e_inject_intent.sh` | [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) | Builds OpenClaw-shaped raw session payloads, pushes via `upsert_behavioral_model_from_raw_sessions`, verifies predictions |
| `tests/e2e_inject_intent.sh` | [edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) | Generates three synthetic Claude Code transcripts (API / shell / git), runs extrapolator, polls model |
| `tests/e2e_inject_intent.sh` | [edamame_claude_desktop](https://github.com/edamametechnologies/edamame_claude_desktop) | Generates synthetic Claude Desktop transcripts, runs extrapolator, polls model |
| `tests/e2e_inject_intent.sh` | [edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) | Generates synthetic Cursor-format JSONL transcripts, runs `cursor_extrapolator`, polls model |

### 2. CVE / Divergence E2E (`--focus cve`)

Tests the **system-plane** detection pipeline: Python trigger scripts
simulate real-world attack patterns (network egress, credential access,
process behavior) while `edamame_cli` verifies that EDAMAME detects and
classifies the resulting activity.

Twelve scenarios, each in `triggers/trigger_<name>.py`:

| Scenario | Trigger script | Threat model | Detection mechanism |
|----------|---------------|--------------|---------------------|
| `blacklist_comm` | `trigger_blacklist_comm.py` | Known-bad IP communication (FireHOL CIDRs) | Blacklist matching (FireHOL IP ranges) + skill_supply_chain if L7 |
| `cve_token_exfil` | `trigger_cve_token_exfil.py` | CVE-2025-52882 / CVE-2026-25253 token exfil | token_exfiltration (anomalous session + sensitive open_files) |
| `cve_sandbox_escape` | `trigger_cve_sandbox_escape.py` | CVE-2026-24763 sandbox escape | sandbox_exploitation (parent_process_path in /tmp/) |
| `divergence` | `trigger_divergence.py` | Undeclared network destinations | Divergence engine (unexplained_destinations > 5) |
| `memory_poisoning` | `trigger_memory_poisoning.py` | Palo Alto Unit 42 memory poisoning | token_exfiltration (anomalous session + sensitive open_files) |
| `goal_drift` | `trigger_goal_drift.py` | Meta AI researcher incident (runaway agent) | Divergence engine (burst connections > 5 unexplained) |
| `credential_sprawl` | `trigger_credential_sprawl.py` | OpenClaw #9627 + AMOS infostealer | token_exfiltration (multi-category credential labels) |
| `supply_chain_exfil` | `trigger_supply_chain_exfil.py` | [litellm 1.82.8 PyPI compromise](https://github.com/BerriAI/litellm/issues/24512) (March 2026) | credential_harvest (9-category credential + crypto harvest + HTTP POST octet-stream exfil; anomaly-independent) |
| `npm_rat_beacon` | `trigger_npm_rat_beacon.py` | axios 1.14.1/0.30.4 npm supply chain RAT (31 March 2026) | token_exfiltration (Base64 JSON beacon + legacy IE UA + npm credential open_files) |
| `file_events` | `trigger_file_events.py` | CVE-2025-30066 file system tampering (tj-actions/changed-files) | file_system_tampering (FIM sensitive file create/modify + temp directory file creation) |
| `temp_modify` | `trigger_temp_modify.py` | Two-phase staged-payload drop: benign placeholder in /tmp followed by malicious overwrite (originally catalogued as evasion scenario 3) | file_system_tampering via content-scan on FIM modify events (script_like / network_command_like heuristics) |
| `nonsensitive_path` | `trigger_nonsensitive_path.py` | Credentials staged outside the sensitive-path database (~/workspace/, IDE caches) while exfiltrating over routine HTTPS (originally catalogued as evasion scenario 4) | sensitive_material_egress (live_open_files + secret_content_scan; anomaly-independent) |

Adversarial evasion scenarios (iForest anomaly blind spots) are tracked separately
in `edamame_core/tests/evasion/` rather than in the E2E CVE suite. Scenarios whose
detection path depends on probabilistic ML scoring (e.g. slow-rate HTTP POST beacons,
MCPTox-style downstream effects) belong there because their pass/fail on CI is not
deterministic. Scenarios whose deterministic detection path has been closed (temp
modify content-scan, non-sensitive-path live open-file scan) graduate here as
regression tests. See `edamame_core/ADVERSARIAL.md` (BS-8) for the current catalog.

## Orchestration Scripts

### `run_demo.sh`

Full interactive demo orchestrator. Provisions packages, seeds behavioral
models with real agent activity, then cycles through CVE and/or divergence
scenarios with `edamame_cli` baseline capture and recovery verification.
Use `--focus vuln|divergence|all` to select which demo category to run.
Repo paths for the staged packages are resolved through `supported_agents.py`,
so the demo follows the same registry metadata as the automated harness.
See [DEMO.md](DEMO.md) for a step-by-step reproduction guide.

```bash
# Run all scenarios (default). --agent-type is optional (defaults to
# openclaw, overridable via EDAMAME_AGENT_TYPE) -- omit it unless you
# want to point triggers at a different agent's state directory.
bash tests/e2e/run_demo.sh \
  --iterations 1 \
  --scenario-duration 150 \
  --divergence-duration 90

# Vulnerability detection demo only (no model seeding needed)
bash tests/e2e/run_demo.sh --focus vuln

# Divergence detection demo only (seeds models + injects intent first)
bash tests/e2e/run_demo.sh --focus divergence
```

The `--focus` flag selects which demo category to run:

| Mode | Scenarios | Prep |
|------|-----------|------|
| `vuln` | CVE/vulnerability triggers (blacklist, token-exfil, sandbox-escape, memory-poisoning, credential-sprawl, supply-chain-exfil, npm-rat-beacon, file-events, temp-modify, nonsensitive-path) | Baseline capture only |
| `divergence` | Divergence triggers (divergence, goal-drift) | Seeds behavioral models + injects intent |
| `all` | Both (default) | Seeds behavioral models + injects intent |

Key capabilities:
- Provisions Cursor, Claude Code, and OpenClaw packages from local source
- Seeds behavioral models via agent CLIs and package extrapolators (divergence / all modes)
- Captures `edamame_cli` baseline before each scenario (blacklisted, anomalous,
  active threats, advisor todos, divergence verdict)
- Runs trigger, waits for EDAMAME ingestion, takes post-scenario snapshot
- Cleans up and waits for EDAMAME state to recover to baseline

### `run_e2e_harness.sh`

Automated multi-round harness for CI and long-run verification. No
provisioning; assumes packages are already installed. Intent-capable agents,
repo overrides, and valid `--agent-type` values all come from the
supported-agent registry.

```bash
bash tests/e2e/run_e2e_harness.sh \
  --focus both \
  --duration-seconds 7200 \
  --parallel-intent
```

Key capabilities:
- Runs intent and/or CVE suites in configurable rounds
- **Fatal detection verification**: after each CVE trigger, the harness
  forces a vulnerability detector tick and asserts the expected detection
  was produced. Missing detections cause a hard test failure (non-zero exit).
  Retry logic (5 attempts, 30s apart) accounts for L7 attribution timing
  (tuned against macOS but applied uniformly on Linux and Windows) and does
  not paper over broken scenarios.
- Per-leg diagnostics: each intent leg writes `round_<n>_<agent>.log` and
  `round_<n>_<agent>_diag.json` on failure
- Merge analysis: records `get_behavioral_model` contributor slices and
  prediction counts grouped by producer
- Structured reporting: `report.jsonl` (one JSON object per round) and
  `SUMMARY.md` rollup

## Supported-Agent Registry

`agent_security/supported_agents/index.json` is the source of truth for:

- Supported `agent_type` values accepted by the E2E harnesses
- Repo locations and per-agent override environment variables
- Repo-local install, uninstall, and healthcheck script paths
- Intent injection scripts and per-agent timeouts

`tests/e2e/supported_agents.py` exposes this registry to shell scripts so
`run_demo.sh` and `run_e2e_harness.sh` can stay data-driven instead of
duplicating agent lists in bash.

## Trigger Script Architecture

### Parameterization

All triggers accept `--agent-type <supported-agent-type>` (default:
`openclaw`, or read from `EDAMAME_AGENT_TYPE` env var). The registry-backed
harnesses currently validate against `openclaw`, `cursor`, `claude_code`,
`claude_desktop`, and `codex`. This determines:

- **STATE_DIR**: `/tmp/edamame_{agent_type}_demo`
- **File prefix**: `demo_{agent_type}_` (for `~/.ssh/`, `~/.aws/`, etc.)
- **Content prefix**: `DEMO_{AGENT_TYPE}_` (for file content strings)

The `--state-dir` override is kept for backwards compatibility.

### Conventions

- **PID_FILE**: `<scenario>.pid` inside STATE_DIR, used by cleanup to kill
  background processes

- **CREATED_MARKER**: `<scenario>.created` inside STATE_DIR, tracks files
  created by the trigger for cleanup

- **`--duration` flag**: All triggers accept `--duration <seconds>` to control
  how long the simulated attack runs

### Signal Generation

Each trigger generates detectable signals on one or more channels:

| Channel | How triggers generate it | What EDAMAME detects |
|---------|------------------------|---------------------|
| Network sessions | TCP connections to undeclared destinations | `get_anomalous_sessions`, `get_blacklisted_sessions`, `get_current_sessions` |
| Sensitive file access | Opens demo credential files (`~/.ssh/`, `~/.aws/`, etc.) | `SensitivePathsDB` in `flodbadd` L7 enrichment |
| Process attribution | Trigger process appears in `l7.cmd` field | Session-to-process linkage in capture pipeline |
| Divergence | Undeclared destinations not in behavioral model | `get_divergence_verdict` returns non-Clean verdict |
| File integrity | Creates/modifies/deletes sensitive files in FIM-watched dirs | `get_file_events` returns events with `is_sensitive=true` |

## Verification with edamame_cli

The scripts use `edamame_cli rpc <method>` to verify detection. Key methods:

| RPC Method | Arguments | Returns |
|-----------|-----------|---------|
| `get_anomalous_sessions` | none | Sessions classified as anomalous by ML (iForest) |
| `get_blacklisted_sessions` | none | Sessions matching blacklist databases |
| `get_current_sessions` | none | All active sessions with L7 attribution |
| `get_score` | `'[false]'` (complete_only=false) | Security score with `active` threat list |
| `get_advisor` | none | Advisor state with `todo_list` |
| `get_divergence_verdict` | none | Current divergence classification |
| `get_behavioral_model` | none | Current merged behavioral model |
| `get_vulnerability_findings` | none | Vulnerability detector findings |
| `get_file_events` | none | FIM snapshot with events, sensitive_events, monitoring status |
| `get_file_monitor_status` | none | FIM watcher status (is_monitoring, watch_paths, event_count) |
| `clear_file_events` | none | Clears all stored FIM events |

## Directory Layout

```
tests/e2e/
  triggers/
    _common.py                     # Shared agent-type resolution helpers
    trigger_blacklist_comm.py
    trigger_cve_token_exfil.py
    trigger_cve_sandbox_escape.py
    trigger_divergence.py
    trigger_memory_poisoning.py
    trigger_goal_drift.py
    trigger_credential_sprawl.py
    trigger_supply_chain_exfil.py
    trigger_npm_rat_beacon.py
    trigger_file_events.py
    trigger_temp_modify.py
    trigger_nonsensitive_path.py
    cleanup.py
  run_demo.sh                      # Full demo orchestrator
  run_e2e_harness.sh               # Automated E2E harness
  supported_agents.py              # Registry helper for repo/path resolution
  E2E_TESTS.md                     # This document (architecture reference)
  DEMO.md                          # Step-by-step demo reproduction guide

Intent injection scripts (one per agent repo):
  edamame_openclaw/tests/e2e_inject_intent.sh
  edamame_claude_code/tests/e2e_inject_intent.sh
  edamame_claude_desktop/tests/e2e_inject_intent.sh
  edamame_cursor/tests/e2e_inject_intent.sh

Registry source of truth:
  supported_agents/index.json
```

## Duration and Timing

| Parameter | Demo default | Harness default | Purpose |
|-----------|-------------|-----------------|---------|
| `--scenario-duration` | 75s | 45s | How long non-divergence triggers run |
| `--divergence-duration` | 45s | 30s | How long divergence + goal_drift triggers run |
| `--post-wait` | 20s | 15s | Wait after trigger for EDAMAME ingestion |
| `--cooldown` | 10s | 8s | Pause between scenarios |
| `--verify-timeout` | 180s | N/A | Max wait for recovery to baseline (demo only) |

Divergence-class scenarios (`divergence`, `goal_drift`) use shorter durations
because they rely on connection count rather than sustained traffic volume.

## Adding a New Scenario

1. Create `triggers/trigger_<name>.py` with:
   - Import from `_common` and add `--agent-type` argument
   - `PID_FILE` and `CREATED_MARKER` constants
   - `--duration` and `--interval` argparse flags
   - Cleanup of created files and processes on exit

2. Update `triggers/cleanup.py`:
   - Add the PID file name to `PID_FILES`
   - Add the created marker to `CREATED_MARKERS`

3. Update `run_demo.sh`:
   - Add scenario name to `VULN_SCENARIOS` or `DIVERGENCE_SCENARIOS` array
   - Add duration classification in the `case` statement if not default

4. Update `run_e2e_harness.sh`:
   - Add scenario name to `scenarios` array in `run_cve_suite()`
   - Add duration classification in the `case` statement if not default

5. Document the scenario in this file.

## Prerequisites

- macOS, Linux, or Windows (Git Bash / WSL). macOS remains the primary
  validation target; the same bash scripts run on all three platforms and no
  PowerShell port is required.
- EDAMAME Security app running with MCP enabled on port 3000
- `edamame_cli` built (`../edamame_cli/target/release/edamame_cli`)
- `python3`, `node`, `curl`
- For intent suite: agentic/LLM configured in the EDAMAME app
- For demo script: `openclaw` CLI (OpenClaw), `claude` CLI + `ANTHROPIC_API_KEY`
  (Claude Code). Both are optional -- when the CLIs are absent (typical on
  Windows), `run_demo.sh` auto-pairs OpenClaw via `edamame_cli` RPC.

### Platform notes

- **Linux**: packet capture requires `CAP_NET_RAW` or root; the harness prints
  a warning if neither is present.
- **Windows (Git Bash / WSL)**: native `pkill` is not always available; both
  `run_demo.sh` and `run_e2e_harness.sh` detect this and fall back to
  `taskkill` via a small Python shim. Packet capture requires Npcap and an
  elevated session -- start Git Bash / WSL as Administrator if capture RPCs
  fail.
- **Plugin install paths** are resolved through
  `tests/e2e/supported_agents.py resolve-paths`, which mirrors each plugin's
  `setup/install.sh` for Darwin, Linux (XDG), and Windows
  (`APPDATA`/`LOCALAPPDATA`). The harness consumes the resolved
  `config_home`, `data_home`/`install_root`, and `state_home` separately, so
  Linux XDG layouts are respected rather than flattened.
- **OpenClaw PSK**: `run_demo.sh` now defaults `OPENCLAW_PSK` to the path
  `edamame_openclaw/setup/pair.sh` actually writes
  (`~/.openclaw/edamame-openclaw/state/edamame-mcp.psk`), not the legacy
  `~/.edamame_psk` location. The env var still overrides the default.

## Troubleshooting

**`edamame_cli` method not found**: Run `edamame_cli list-methods` to see
available RPC methods. Method names may change between core versions.

**Trigger has no visible effect**: Check `edamame_cli rpc get_current_sessions`
for the trigger's destination IP/port. Sessions may be classified as
`anomaly:normal` initially; the ML anomaly detector needs sufficient traffic
volume for higher classification.

**Divergence verdict stays Clean during trigger**: The divergence engine
requires a behavioral model to compare against. Run the intent suite first
or seed models via the demo script's agent-activity phase.

**Recovery timeout**: Some sessions persist in EDAMAME's capture state after
the trigger process exits. Increase `--verify-timeout` or use
`--skip-edamame-cli` to bypass recovery checks.
