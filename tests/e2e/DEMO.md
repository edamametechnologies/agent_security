# Demo Guide -- Vulnerability Detection and Divergence Detection

Reproducible demos for EDAMAME's two detection planes. Each demo can be run
independently or combined. All triggers are user-space, reversible, and
automatically cleaned up on exit.

## Prerequisites

### Tools

| Requirement | Notes |
|-------------|-------|
| macOS | Both demos are macOS-validated |
| EDAMAME Security app **or** `edamame_posture` daemon | MCP enabled on port 3000 (override with `EDAMAME_MCP_PORT`) |
| `edamame_cli` | Built from `../edamame_cli` or on `$PATH` |
| `python3` | Runs the trigger scripts |
| `node` | Package extrapolators (divergence demo) |
| `curl` | Health check |

### EDAMAME App Setup Checklist

Before running any demo, verify the following inside the EDAMAME app:

- [ ] **Traffic capture is ON** -- Go to the **System** tab and confirm
      traffic capture is running (sessions should be visible). Without
      capture, the vulnerability detector has no network sessions to analyze.

- [ ] **LLM is configured** -- Go to **AI > AI Settings** and configure an
      LLM provider. Two options:
  - *EDAMAME Portal*: Sign in to EDAMAME Cloud (OAuth) under the
    "EDAMAME Portal" section. This routes LLM calls through the
    EDAMAME Portal proxy.
  - *Own LLM*: Configure your own provider (OpenAI API key, Anthropic
    key, or local Ollama endpoint) under the LLM provider section.
  - The app shows "Sign in to EDAMAME Cloud or configure your own LLM
    to enable" if neither is set.

- [ ] **AI Security Watchdog or AI Security Assistant is ON** -- On the
      home **Overview** screen, activate either:
  - *AI Security Watchdog*: monitors and recommends (read-only analysis).
  - *AI Security Assistant*: monitors and auto-fixes safe issues.
  - Either mode starts the vulnerability detection loop and the
    divergence engine. You can also enable these from the **AI >
    Security Agent** sub-tab.

If using `edamame_posture` CLI instead of the app:

```bash
# Start the daemon with LLM configured (Portal API key)
edamame_posture background-start-disconnected \
  --llm-api-key "$EDAMAME_LLM_API_KEY"

# Or with own LLM (e.g. Ollama)
edamame_posture background-start-disconnected \
  --llm-provider ollama --llm-api-key ""

# Start the agentic loop (vulnerability + divergence detection)
edamame_posture background-agentic-start
```

### Verify EDAMAME Is Ready

```bash
# MCP health check
curl -sf http://127.0.0.1:3000/health
# Expected: OK

# Sessions are being captured
edamame_cli rpc get_current_sessions --pretty | head -5
# Should show active sessions (not an empty list)

# LLM is configured (provider should not be empty/none)
edamame_cli rpc agentic_get_llm_config --pretty
```

### Additional Requirements (Divergence Demo)

| Requirement | Notes |
|-------------|-------|
| LLM provider active | Behavioral model processing requires LLM calls |
| `openclaw` CLI (default) | Or set `--agent-type cursor` / `claude_code` |

## Quick Start

```bash
cd agent_security/tests/e2e

# Vulnerability detection demo only
bash run_demo.sh --focus vuln --skip-provision --auto-pair

# Divergence detection demo only
bash run_demo.sh --focus divergence --skip-provision --auto-pair

# Both demos combined (default)
bash run_demo.sh --focus all --skip-provision --auto-pair
```

Add `--dry-run` to preview commands without executing.

---

## Vulnerability Detection Demo

**What it tests:** EDAMAME's system-plane CVE and threat detection pipeline --
blacklist matching, ML anomaly detection, token exfiltration, sandbox escape,
credential harvest, supply chain compromise, and file integrity monitoring.

**No behavioral model needed.** The vulnerability detector operates on live
network sessions and file events independently of the reasoning plane.

### Scenarios

| Scenario | Attack pattern | Expected detection |
|----------|---------------|-------------------|
| `blacklist_comm` | TCP to known-bad FireHOL CIDRs | Blacklisted session + `skill_supply_chain` |
| `cve_token_exfil` | Long-lived high-port egress with sensitive files open | `token_exfiltration` (CVE-2025-52882 / CVE-2026-25253) |
| `cve_sandbox_escape` | Process spawned from `/tmp/` with network egress | `sandbox_exploitation` (CVE-2026-24763) |
| `memory_poisoning` | Anomalous egress with credential file handles | `token_exfiltration` |
| `credential_sprawl` | Multi-category credential access (SSH + AWS + cloud + crypto) | `credential_harvest` |
| `tool_poisoning_effects` | HTTP POST exfiltration with sensitive file handles | `token_exfiltration` |
| `supply_chain_exfil` | 9-category credential harvest + HTTP POST octet-stream | `credential_harvest` |
| `npm_rat_beacon` | Base64 JSON beacon with legacy IE UA + npm credentials | `token_exfiltration` |
| `file_events` | Sensitive file create/modify in FIM-watched directories | `file_system_tampering` |

### Run

```bash
bash run_demo.sh --focus vuln --skip-provision --auto-pair
```

Common options:

```bash
--scenario-duration 150    # How long each trigger runs (seconds, default: 150)
--post-wait 20             # Wait for EDAMAME ingestion after trigger (default: 20)
--cooldown 10              # Pause between scenarios (default: 10)
--iterations 2             # Repeat the full cycle
--agent-type openclaw      # Agent identity for state directory (default: openclaw)
```

### Verify Manually

While a trigger is running (or shortly after), use `edamame_cli`:

```bash
# Anomalous sessions (ML-flagged)
edamame_cli rpc get_anomalous_sessions --pretty

# Blacklisted sessions
edamame_cli rpc get_blacklisted_sessions --pretty

# Vulnerability findings
edamame_cli rpc get_vulnerability_findings --pretty

# Security score with active threats
edamame_cli rpc get_score '[false]' --pretty

# File integrity events (file_events scenario)
edamame_cli rpc get_file_events --pretty
```

### Run a Single Trigger Manually

Each trigger is a standalone Python script:

```bash
cd triggers

# Token exfiltration -- runs for 120 seconds
python3 trigger_cve_token_exfil.py --agent-type openclaw --duration 120

# Blacklist communication -- runs until interrupted
python3 trigger_blacklist_comm.py --agent-type openclaw --duration 0
# Ctrl-C to stop

# Cleanup all demo state
python3 cleanup.py --agent-type openclaw
```

---

## Divergence Detection Demo

**What it tests:** EDAMAME's reasoning-plane divergence engine -- compares
an agent's declared behavioral intent (what it said it would do) against
live system-plane telemetry (what is actually happening on the network).

**Requires a behavioral model.** The divergence engine needs a populated
model to compare against. The demo script seeds this automatically by
running agent extrapolators and injecting synthetic intent before the
divergence triggers fire.

### Scenarios

| Scenario | Attack pattern | Expected detection |
|----------|---------------|-------------------|
| `divergence` | Sustained UDP egress to 15 undeclared public destinations | Divergence verdict: `DIVERGENCE` (unexplained_destinations > 5) |
| `goal_drift` | Burst of connections to undeclared destinations | Divergence verdict: `DIVERGENCE` (burst > 5 unexplained) |

### Run

```bash
bash run_demo.sh --focus divergence --skip-provision --auto-pair
```

Common options:

```bash
--divergence-duration 90   # How long divergence triggers run (seconds, default: 90)
--skip-intent              # Skip synthetic intent injection (use existing model)
--agent-type openclaw      # Agent identity (default: openclaw)
```

### What Happens During Prep

Before the divergence triggers fire, the script:

1. Seeds behavioral models via agent CLIs and package extrapolators
2. Injects synthetic intent through each agent's `e2e_inject_intent.sh`
3. Verifies that `get_behavioral_model` returns predictions for all
   registered intent-capable agents

This ensures the divergence engine has a baseline to compare against.

### Verify Manually

```bash
# Current divergence verdict
edamame_cli rpc get_divergence_verdict --pretty

# Current behavioral model (predictions from intent)
edamame_cli rpc get_behavioral_model --pretty

# Active sessions (look for undeclared destinations)
edamame_cli rpc get_current_sessions --pretty
```

---

## Combined Demo

Runs the full pipeline: seed models, inject intent, then cycle through all
11 scenarios (9 vulnerability + 2 divergence).

```bash
bash run_demo.sh --focus all --skip-provision --auto-pair
```

This is equivalent to the default behavior (omitting `--focus`).

---

## Common Options Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--focus MODE` | `all` | `vuln`, `divergence`, or `all` |
| `--agent-type NAME` | `openclaw` | Agent identity for trigger state and intent injection |
| `--iterations N` | `1` | Number of full scenario cycles |
| `--scenario-duration SEC` | `150` | Duration for vulnerability triggers |
| `--divergence-duration SEC` | `90` | Duration for divergence triggers |
| `--post-wait SEC` | `20` | Wait for EDAMAME ingestion after each trigger |
| `--cooldown SEC` | `10` | Pause between scenarios |
| `--verify-timeout SEC` | `180` | Max wait for recovery to baseline |
| `--skip-provision` | off | Skip package refresh (use existing installs) |
| `--skip-intent` | off | Skip intent injection (use existing behavioral model) |
| `--skip-agents` | off | Skip Claude/OpenClaw agent prompts |
| `--skip-edamame-cli` | off | Skip `edamame_cli` verification snapshots |
| `--auto-pair` | off | Auto-approve MCP pairing via RPC (no UI) |
| `--dry-run` | off | Print commands without executing |
| `--strict` | off | Treat optional failures as fatal |

## Cleanup

All demo state is automatically cleaned up on exit (including Ctrl-C).
To clean up manually:

```bash
python3 triggers/cleanup.py --agent-type openclaw
```

Existing configs are backed up under `~/.edamame_demo_backups/<timestamp>/`
before each run.

## Troubleshooting

**Trigger has no visible effect:** Check `edamame_cli rpc get_current_sessions --pretty`
for the trigger's destination IP/port. The ML anomaly detector may need a few
seconds of sustained traffic before flagging sessions.

**Divergence verdict stays `CLEAN`:** The divergence engine requires a
behavioral model. Use `--focus divergence` (not `--focus vuln`) or run intent
injection separately first.

**Recovery timeout after cleanup:** Some sessions persist briefly in EDAMAME's
capture state after the trigger exits. Increase `--verify-timeout` or add
`--skip-edamame-cli` to bypass recovery checks.

**`edamame_cli` method not found:** Run `edamame_cli list-methods` to check
available RPC methods. Method names may change between core versions.

## See Also

- [E2E_TESTS.md](E2E_TESTS.md) -- Full E2E architecture, trigger internals, and adding new scenarios
- [run_demo.sh](run_demo.sh) -- Demo orchestrator source
- [run_e2e_harness.sh](run_e2e_harness.sh) -- Automated CI harness
