#!/usr/bin/env bash
#
# Local EDAMAME agent-security demo orchestrator for macOS.
#
# For scheduled multi-round intent E2E + merge reports without re-provisioning, see
# run_e2e_harness.sh (--focus intent|cve|both).
#
# This script refreshes the latest local EDAMAME integrations from source,
# stages the OpenClaw/Cursor/Claude Code plugin surfaces, and runs a reversible
# user-space demo loop that mixes:
#   - real agent-driven CLI activity
#   - package-side intent export / verdict reads
#   - CVE and divergence trigger injectors
#   - direct EDAMAME CLI snapshots and recovery verification
#
# Safety constraints:
#   - user-space only
#   - no privileged operations
#   - only reversible demo injectors from the integration repos
#   - every exit path triggers demo cleanup
#
# Notes:
#   - Cursor does not currently have a general-purpose CLI agent surface, so the
#     script uses the package's real service CLIs (`cursor_extrapolator`,
#     `verdict_reader`, `healthcheck`).
#   - Claude Code agent calls use the local source plugin via `claude --plugin-dir`
#     so the demo exercises the latest local checkout instead of a published build.
#   - OpenClaw provisioning syncs both the extension and the bundled skills,
#     mirroring the repo's VM provisioner.
#   - The default injector source is `openclaw` because it has the most reliable
#     CLI lineage for local macOS demos. `cursor` and `claude` are available as
#     experimental alternatives.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_agent_security_demo.sh [options]

Refresh local EDAMAME integrations and run a reversible demo loop on macOS.

Options:
  --focus MODE              Which demo to run: vuln, divergence, or all. Default: all
                            vuln: CVE/vulnerability detection scenarios only.
                            divergence: Divergence detection scenarios only (seeds
                              behavioral models and injects intent first).
                            all: Both vulnerability and divergence scenarios.
  --workspace-root PATH     Workspace root used for Cursor/Claude package configs.
                            Default: this repo root.
  --iterations N            Number of full scenario rounds. Default: 1
  --scenario-duration SEC   Duration for blacklist/token/sandbox scenarios.
                            Default: 75
  --divergence-duration SEC Duration for divergence scenario. Default: 45
  --post-wait SEC           Extra wait after each injector before readouts.
                            Default: 20
  --cooldown SEC            Pause between scenarios. Default: 10
  --verify-timeout SEC      Max time to wait for EDAMAME state to return to the
                            pre-scenario baseline after cleanup. Default: 180
  --verify-interval SEC     Poll interval for EDAMAME CLI recovery checks.
                            Default: 10
  --agent-type NAME         Agent type for trigger scripts; validated against the
                            supported-agent registry. Default: openclaw
  --skip-provision          Skip package/plugin refresh and use existing installs.
  --skip-pair               Skip all pairing (even auto-pair).
  --auto-pair               Auto-approve pairing via edamame_cli RPC (no UI approval needed).
  --skip-agents             Skip Claude/OpenClaw agent prompts.
  --skip-intent             Skip intent injection (e2e_inject_intent.sh per agent).
  --intent-timeout SEC      Max time per intent injection script. Default: 300
  --skip-edamame-cli        Skip direct edamame_cli snapshots and verification.
  --provision-only          Refresh local installs and exit without running scenarios.
  --force-pair              Re-run OpenClaw app-mediated pairing even if ~/.edamame_psk exists.
  --strict                  Treat optional-surface failures as fatal.
  --dry-run                 Print planned commands without executing them.
  -h, --help                Show this help.

Prerequisites:
  - macOS
  - EDAMAME Security app or edamame_posture daemon with MCP on port 3000 (override with EDAMAME_MCP_PORT)
  - python3, node, curl
  - openclaw CLI for OpenClaw provisioning and agent prompts
  - claude CLI + ANTHROPIC_API_KEY for Claude Code agent prompts
  - edamame_cli for direct EDAMAME verification (unless --skip-edamame-cli)

Behavior:
  1. Refresh Cursor and Claude package installs from the local repos.
  2. Merge the rendered Cursor MCP snippet into ~/.cursor/mcp.json.
  3. Sync the OpenClaw extension + skills into ~/.openclaw and enable the plugin.
  4. Reuse or request an app-issued EDAMAME MCP token via setup/pair.sh.
  5. Depending on --focus:
     vuln:       Skip model seeding/intent, run CVE scenarios only.
     divergence: Seed behavioral models, inject intent, run divergence scenarios.
     all:        Seed models, inject intent, run all scenarios (default).
  6. Verify every scenario with edamame_cli and wait for alert/session counts to
     return to the pre-scenario baseline after cleanup.

Backups:
  - Existing ~/.cursor/mcp.json and ~/.openclaw/edamame assets are backed up under
    ~/.edamame_demo_backups/<timestamp> before changes are applied.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIGGERS_DIR="$ROOT_DIR/triggers"
SUPPORTED_AGENT_HELPER="$ROOT_DIR/supported_agents.py"

WORKSPACE_ROOT="${WORKSPACE_ROOT:-$ROOT_DIR/../../..}"
FOCUS="all"
ITERATIONS=1
SCENARIO_DURATION=150
DIVERGENCE_DURATION=90
POST_WAIT=20
COOLDOWN=10
VERIFY_TIMEOUT=180
VERIFY_INTERVAL=10
AGENT_TYPE="openclaw"

SKIP_PROVISION=0
SKIP_PAIR=0
AUTO_PAIR=0
SKIP_AGENTS=0
SKIP_INTENT=0
INTENT_TIMEOUT=300
SKIP_EDAMAME_CLI=0
PROVISION_ONLY=0
FORCE_PAIR=0
STRICT=0
DRY_RUN=0

EDAMAME_CLI_BIN_CACHE=""
EDAMAME_BASELINE_BLACKLISTED=0
EDAMAME_BASELINE_ANOMALOUS=0
EDAMAME_BASELINE_ACTIVE_THREATS=0
EDAMAME_BASELINE_TODOS=0
EDAMAME_BASELINE_VERDICT="unknown"
EDAMAME_BASELINE_CAPTURED=0

while (($# > 0)); do
  case "$1" in
    --focus)
      FOCUS="$2"
      shift 2
      ;;
    --workspace-root)
      WORKSPACE_ROOT="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --scenario-duration)
      SCENARIO_DURATION="$2"
      shift 2
      ;;
    --divergence-duration)
      DIVERGENCE_DURATION="$2"
      shift 2
      ;;
    --post-wait)
      POST_WAIT="$2"
      shift 2
      ;;
    --cooldown)
      COOLDOWN="$2"
      shift 2
      ;;
    --verify-timeout)
      VERIFY_TIMEOUT="$2"
      shift 2
      ;;
    --verify-interval)
      VERIFY_INTERVAL="$2"
      shift 2
      ;;
    --agent-type)
      AGENT_TYPE="$2"
      shift 2
      ;;
    --skip-provision)
      SKIP_PROVISION=1
      shift
      ;;
    --skip-pair)
      SKIP_PAIR=1
      shift
      ;;
    --auto-pair)
      AUTO_PAIR=1
      shift
      ;;
    --skip-agents)
      SKIP_AGENTS=1
      shift
      ;;
    --skip-intent)
      SKIP_INTENT=1
      shift
      ;;
    --intent-timeout)
      INTENT_TIMEOUT="$2"
      shift 2
      ;;
    --skip-edamame-cli)
      SKIP_EDAMAME_CLI=1
      shift
      ;;
    --provision-only)
      PROVISION_ONLY=1
      shift
      ;;
    --force-pair)
      FORCE_PAIR=1
      shift
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

APP_ROOT="${EDAMAME_APP_ROOT:-$ROOT_DIR/../../../edamame_app}"
CLI_REPO="${EDAMAME_CLI_REPO:-$ROOT_DIR/../../../edamame_cli}"
CURSOR_REPO=""
CLAUDE_REPO=""
CLAUDE_DESKTOP_REPO=""
OPENCLAW_REPO=""

CURSOR_HOME="${HOME}/Library/Application Support/cursor-edamame"
CLAUDE_HOME="${HOME}/Library/Application Support/claude-code-edamame"
CLAUDE_DESKTOP_HOME="${HOME}/Library/Application Support/claude-desktop-edamame"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CURSOR_CONFIG="${CURSOR_HOME}/config.json"
CLAUDE_CONFIG="${CLAUDE_HOME}/config.json"
CLAUDE_DESKTOP_CONFIG="${CLAUDE_DESKTOP_HOME}/config.json"
CURSOR_PSK="${CURSOR_HOME}/state/edamame-mcp.psk"
CLAUDE_PSK="${CLAUDE_HOME}/state/edamame-mcp.psk"
CLAUDE_DESKTOP_PSK="${CLAUDE_DESKTOP_HOME}/state/edamame-mcp.psk"
OPENCLAW_PAIRING_PSK="${HOME}/.openclaw/edamame-openclaw/state/edamame-mcp.psk"
CURSOR_MCP_TARGET="${CURSOR_MCP_TARGET:-$HOME/.cursor/mcp.json}"
OPENCLAW_PSK="${OPENCLAW_PSK:-$HOME/.edamame_psk}"

RUN_TS="$(date +"%Y%m%d-%H%M%S")"
BACKUP_ROOT="${HOME}/.edamame_demo_backups/${RUN_TS}"
mkdir -p "$BACKUP_ROOT"

VULN_SCENARIOS=(
  "blacklist_comm"
  "cve_token_exfil"
  "cve_sandbox_escape"
  "memory_poisoning"
  "credential_sprawl"
  "tool_poisoning_effects"
  "supply_chain_exfil"
  "npm_rat_beacon"
  "file_events"
)

DIVERGENCE_SCENARIOS=(
  "divergence"
  "goal_drift"
)

SCENARIOS=()

log() {
  printf '\n[%s] %s\n' "$(date +"%H:%M:%S")" "$*"
}

warn() {
  printf '\n[%s] WARNING: %s\n' "$(date +"%H:%M:%S")" "$*" >&2
}

die() {
  printf '\n[%s] ERROR: %s\n' "$(date +"%H:%M:%S")" "$*" >&2
  exit 1
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

require_command() {
  local cmd="$1"
  if ! have_command "$cmd"; then
    die "Required command not found: $cmd"
  fi
}

optional_failure() {
  local message="$1"
  if [[ "$STRICT" -eq 1 ]]; then
    die "$message"
  fi
  warn "$message"
}

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

run_timeout() {
  local timeout_secs="$1"
  shift
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '  # timeout=%ss\n' "$timeout_secs"
    return 0
  fi
  python3 - "$timeout_secs" "$@" <<'PY'
import subprocess
import sys

timeout = float(sys.argv[1])
cmd = sys.argv[2:]
try:
    completed = subprocess.run(cmd, timeout=timeout)
    raise SystemExit(completed.returncode)
except subprocess.TimeoutExpired:
    print(f"Timed out after {timeout:.0f}s: {' '.join(cmd)}", file=sys.stderr)
    raise SystemExit(124)
PY
}

assert_dir() {
  local path="$1"
  [[ -d "$path" ]] || die "Required directory not found: $path"
}

backup_if_exists() {
  local source_path="$1"
  local backup_path="$2"
  [[ -e "$source_path" ]] || return 0
  mkdir -p "$(dirname "$backup_path")"
  if [[ -e "$backup_path" ]]; then
    return 0
  fi
  run_cmd cp -R "$source_path" "$backup_path"
}

merge_json_file() {
  local target_path="$1"
  local snippet_path="$2"
  local backup_path="$3"

  mkdir -p "$(dirname "$target_path")"
  backup_if_exists "$target_path" "$backup_path"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "+ merge_json_file $snippet_path -> $target_path"
    return 0
  fi

  python3 - "$target_path" "$snippet_path" <<'PY'
import json
import sys
from pathlib import Path

target_path = Path(sys.argv[1])
snippet_path = Path(sys.argv[2])

if target_path.exists():
    try:
        target = json.loads(target_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {target_path}: {exc}")
else:
    target = {}

try:
    snippet = json.loads(snippet_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as exc:
    raise SystemExit(f"Invalid JSON in {snippet_path}: {exc}")

target.setdefault("mcpServers", {})
target["mcpServers"].update(snippet.get("mcpServers", {}))

target_path.write_text(json.dumps(target, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

sync_psk() {
  local destination="$1"
  if [[ ! -f "$OPENCLAW_PSK" ]]; then
    return 1
  fi
  mkdir -p "$(dirname "$destination")"
  run_cmd cp "$OPENCLAW_PSK" "$destination"
  run_cmd chmod 600 "$destination"
}

emit_supported_agent_types() {
  if ! command -v python3 >/dev/null 2>&1 || [[ ! -f "$SUPPORTED_AGENT_HELPER" ]]; then
    printf '%s\n' "$AGENT_TYPE"
    return 0
  fi
  python3 "$SUPPORTED_AGENT_HELPER" types | python3 -c 'import json,sys; [print(t) for t in json.load(sys.stdin)]'
}

supported_agent_types_display() {
  python3 "$SUPPORTED_AGENT_HELPER" types | python3 -c 'import json,sys; print(", ".join(json.load(sys.stdin)))'
}

validate_supported_agent_type() {
  local agent_type="$1"
  python3 "$SUPPORTED_AGENT_HELPER" get-agent --agent-type "$agent_type" >/dev/null 2>&1
}

resolve_agent_repo() {
  local agent_type="$1"
  python3 "$SUPPORTED_AGENT_HELPER" get-agent --agent-type "$agent_type" | python3 -c 'import json,sys; print(json.load(sys.stdin)["repo_path"])'
}

load_registry_context() {
  CURSOR_REPO="$(resolve_agent_repo cursor)"
  CLAUDE_REPO="$(resolve_agent_repo claude_code)"
  CLAUDE_DESKTOP_REPO="$(resolve_agent_repo claude_desktop)"
  OPENCLAW_REPO="$(resolve_agent_repo openclaw)"
}

cleanup_demo_state() {
  pkill -f sandbox_probe 2>/dev/null || true
  pkill -f divergence_probe 2>/dev/null || true

  local cleanup_script="$TRIGGERS_DIR/cleanup.py"
  if [[ -f "$cleanup_script" ]]; then
    local at
    while IFS= read -r at; do
      [[ -n "$at" ]] || continue
      if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "+ python3 $cleanup_script --agent-type $at"
      else
        python3 "$cleanup_script" --agent-type "$at" >/dev/null 2>&1 || true
      fi
    done < <(emit_supported_agent_types)
  fi

  local cli_bin
  if cli_bin="$(find_edamame_cli_bin 2>/dev/null)"; then
    "$cli_bin" rpc clear_vulnerability_history >/dev/null 2>&1 || true
  fi
}

trap cleanup_demo_state EXIT INT TERM

validate_inputs() {
  [[ "$(uname -s)" == "Darwin" ]] || die "This orchestrator currently supports macOS only."
  [[ "$FOCUS" =~ ^(vuln|divergence|all)$ ]] || die "--focus must be one of: vuln, divergence, all"
  [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || die "--iterations must be an integer"
  [[ "$SCENARIO_DURATION" =~ ^[0-9]+$ ]] || die "--scenario-duration must be an integer"
  [[ "$DIVERGENCE_DURATION" =~ ^[0-9]+$ ]] || die "--divergence-duration must be an integer"
  [[ "$POST_WAIT" =~ ^[0-9]+$ ]] || die "--post-wait must be an integer"
  [[ "$COOLDOWN" =~ ^[0-9]+$ ]] || die "--cooldown must be an integer"
  [[ "$VERIFY_TIMEOUT" =~ ^[0-9]+$ ]] || die "--verify-timeout must be an integer"
  [[ "$VERIFY_INTERVAL" =~ ^[0-9]+$ ]] || die "--verify-interval must be an integer"
  [[ "$INTENT_TIMEOUT" =~ ^[0-9]+$ ]] || die "--intent-timeout must be an integer"

  case "$FOCUS" in
    vuln)       SCENARIOS=("${VULN_SCENARIOS[@]}") ;;
    divergence) SCENARIOS=("${DIVERGENCE_SCENARIOS[@]}") ;;
    all)        SCENARIOS=("${VULN_SCENARIOS[@]}" "${DIVERGENCE_SCENARIOS[@]}") ;;
  esac
}

check_prereqs() {
  [[ -f "$SUPPORTED_AGENT_HELPER" ]] || die "Supported-agent helper not found: $SUPPORTED_AGENT_HELPER"
  require_command python3
  require_command node
  require_command curl
  python3 "$SUPPORTED_AGENT_HELPER" validate || die "Supported-agent registry validation failed."
  validate_supported_agent_type "$AGENT_TYPE" || \
    die "--agent-type must be one of: $(supported_agent_types_display)"
  load_registry_context
  assert_dir "$CURSOR_REPO"
  assert_dir "$CLAUDE_REPO"
  assert_dir "$OPENCLAW_REPO"
  if [[ "$SKIP_EDAMAME_CLI" -eq 0 ]]; then
    resolve_edamame_cli_bin >/dev/null
  fi
}

ensure_edamame_app() {
  local port="${EDAMAME_MCP_PORT:-3000}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "+ curl -sf http://127.0.0.1:${port}/health"
    return 0
  fi
  local health
  health="$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null || true)"
  [[ "$health" == "OK" ]] || die "EDAMAME MCP health check failed on port ${port}. Start the app or edamame_posture with MCP enabled (set EDAMAME_MCP_PORT to override)."
}

install_cursor_package() {
  log "Refreshing Cursor package from local source"
  run_cmd bash "$CURSOR_REPO/setup/install.sh" "$WORKSPACE_ROOT"
  merge_json_file \
    "$CURSOR_MCP_TARGET" \
    "$CURSOR_HOME/cursor-mcp.json" \
    "$BACKUP_ROOT/cursor-mcp.json"

  if [[ -f "$OPENCLAW_PSK" ]]; then
    sync_psk "$CURSOR_PSK" || true
  fi
}

install_claude_package() {
  log "Refreshing Claude Code package from local source"
  run_cmd bash "$CLAUDE_REPO/setup/install.sh" "$WORKSPACE_ROOT"
  if [[ -f "$OPENCLAW_PSK" ]]; then
    sync_psk "$CLAUDE_PSK" || true
  fi
  if have_command claude; then
    run_cmd claude plugin validate "$CLAUDE_REPO" || optional_failure "claude plugin validate failed for local source plugin"
  else
    warn "claude CLI not found; local Claude plugin validation and agent prompts will be skipped"
  fi
}

install_openclaw_surface() {
  if ! have_command openclaw; then
    optional_failure "openclaw CLI not found; OpenClaw provisioning and agent prompts will be skipped"
    return 0
  fi

  log "Refreshing OpenClaw extension and skills from local source"

  mkdir -p "$OPENCLAW_HOME/extensions" "$OPENCLAW_HOME/skills"
  backup_if_exists "$OPENCLAW_HOME/extensions/edamame" "$BACKUP_ROOT/openclaw/extensions-edamame"
  backup_if_exists "$OPENCLAW_HOME/extensions/edamame-mcp" "$BACKUP_ROOT/openclaw/extensions-edamame-mcp"
  backup_if_exists "$OPENCLAW_HOME/skills/edamame-extrapolator" "$BACKUP_ROOT/openclaw/skills-edamame-extrapolator"
  backup_if_exists "$OPENCLAW_HOME/skills/edamame-cortex-extrapolator" "$BACKUP_ROOT/openclaw/skills-edamame-cortex-extrapolator"
  backup_if_exists "$OPENCLAW_HOME/skills/edamame-posture" "$BACKUP_ROOT/openclaw/skills-edamame-posture"

  run_cmd rm -rf "$OPENCLAW_HOME/extensions/edamame"
  run_cmd rm -rf "$OPENCLAW_HOME/extensions/edamame-mcp"
  run_cmd mkdir -p \
    "$OPENCLAW_HOME/extensions/edamame/skills/edamame-extrapolator" \
    "$OPENCLAW_HOME/extensions/edamame/skills/edamame-posture"
  run_cmd cp "$OPENCLAW_REPO/extensions/edamame/openclaw.plugin.json" "$OPENCLAW_HOME/extensions/edamame/openclaw.plugin.json"
  run_cmd cp "$OPENCLAW_REPO/extensions/edamame/index.ts" "$OPENCLAW_HOME/extensions/edamame/index.ts"
  # The plugin manifest declares bundled skills relative to the extension root,
  # so stage them there and under ~/.openclaw/skills for compatibility.
  run_cmd cp "$OPENCLAW_REPO/skill/edamame-extrapolator/SKILL.md" "$OPENCLAW_HOME/extensions/edamame/skills/edamame-extrapolator/SKILL.md"
  run_cmd cp "$OPENCLAW_REPO/skill/edamame-posture/SKILL.md" "$OPENCLAW_HOME/extensions/edamame/skills/edamame-posture/SKILL.md"

  run_cmd rm -rf "$OPENCLAW_HOME/skills/edamame-extrapolator"
  run_cmd mkdir -p "$OPENCLAW_HOME/skills/edamame-extrapolator"
  run_cmd cp "$OPENCLAW_REPO/skill/edamame-extrapolator/SKILL.md" "$OPENCLAW_HOME/skills/edamame-extrapolator/SKILL.md"

  run_cmd rm -rf "$OPENCLAW_HOME/skills/edamame-cortex-extrapolator"
  run_cmd mkdir -p "$OPENCLAW_HOME/skills/edamame-cortex-extrapolator"
  run_cmd cp "$OPENCLAW_REPO/skill/edamame-extrapolator/SKILL.md" "$OPENCLAW_HOME/skills/edamame-cortex-extrapolator/SKILL.md"

  run_cmd rm -rf "$OPENCLAW_HOME/skills/edamame-posture"
  run_cmd mkdir -p "$OPENCLAW_HOME/skills/edamame-posture"
  run_cmd cp "$OPENCLAW_REPO/skill/edamame-posture/SKILL.md" "$OPENCLAW_HOME/skills/edamame-posture/SKILL.md"

  run_cmd openclaw plugins enable edamame || optional_failure "openclaw plugins enable edamame failed"
}

auto_pair_via_rpc() {
  local port="${EDAMAME_MCP_PORT:-3000}"
  local cli_bin
  cli_bin="$(find_edamame_cli_bin 2>/dev/null)" || {
    optional_failure "edamame_cli not found; cannot auto-pair"
    return 1
  }

  log "Auto-pairing via HTTP + edamame_cli RPC"
  local response request_id
  response="$(curl -sf -X POST "http://127.0.0.1:${port}/mcp/pair" \
    -H "Content-Type: application/json" \
    -d '{
      "client_name": "E2E Demo Loop",
      "agent_type": "openclaw",
      "agent_instance_id": "e2e-demo-auto",
      "requested_endpoint": "http://127.0.0.1:'"${port}"'/mcp",
      "workspace_hint": null
    }' 2>&1)" || {
    optional_failure "Failed to reach MCP pair endpoint"
    return 1
  }

  request_id="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("request_id",""))' 2>/dev/null)"
  if [[ -z "$request_id" ]]; then
    optional_failure "Pairing request did not return a request_id: $response"
    return 1
  fi

  local approve_json
  approve_json="$("$cli_bin" rpc mcp_approve_pairing "[\"${request_id}\"]" --pretty 2>&1)" || {
    optional_failure "edamame_cli mcp_approve_pairing failed"
    return 1
  }

  local credential
  credential="$(printf '%s' "$approve_json" | python3 -c '
import json, sys
raw = json.load(sys.stdin)
if isinstance(raw, str):
    raw = json.loads(raw)
print(raw.get("client", {}).get("credential", ""))
' 2>/dev/null)"

  if [[ -z "$credential" ]]; then
    optional_failure "Auto-pair approved but no credential returned"
    return 1
  fi

  mkdir -p "$(dirname "$OPENCLAW_PSK")"
  printf '%s' "$credential" > "$OPENCLAW_PSK"
  chmod 600 "$OPENCLAW_PSK"
  log "Auto-pair credential stored in $OPENCLAW_PSK"
  return 0
}

sync_all_psks() {
  sync_psk "$CURSOR_PSK" || true
  sync_psk "$CLAUDE_PSK" || true
  sync_psk "$CLAUDE_DESKTOP_PSK" || true
  sync_psk "$OPENCLAW_PAIRING_PSK" || true
}

ensure_pairing() {
  if [[ "$SKIP_PAIR" -eq 1 ]]; then
    if [[ -f "$OPENCLAW_PSK" ]]; then
      log "Reusing existing EDAMAME MCP credential at $OPENCLAW_PSK"
    else
      warn "No PSK and --skip-pair set; intent injection will fail without a PSK"
    fi
    sync_all_psks
    return 0
  fi

  if [[ "$FORCE_PAIR" -eq 0 && -f "$OPENCLAW_PSK" ]]; then
    log "Reusing existing EDAMAME MCP credential at $OPENCLAW_PSK"
    sync_all_psks
    return 0
  fi

  if [[ "$AUTO_PAIR" -eq 1 ]]; then
    log "Auto-pair requested via --auto-pair"
    auto_pair_via_rpc || die "Auto-pair via RPC failed"
    sync_all_psks
    return 0
  fi

  if have_command openclaw; then
    log "Requesting app-mediated OpenClaw pairing"
    run_cmd bash "$OPENCLAW_REPO/setup/pair.sh" --timeout 90
  else
    log "openclaw CLI not found; attempting auto-pair via RPC"
    auto_pair_via_rpc || die "Pairing failed: neither openclaw CLI nor auto-pair succeeded"
  fi

  if [[ ! -f "$OPENCLAW_PSK" ]]; then
    die "Pairing did not create $OPENCLAW_PSK"
  fi

  sync_all_psks
}

seed_cursor_model() {
  local install_root="$CURSOR_HOME/current"
  [[ -d "$install_root" ]] || return 0
  log "Cursor package: intent export and health check"
  run_cmd node "$install_root/service/cursor_extrapolator.mjs" --config "$CURSOR_CONFIG" --json \
    || optional_failure "Cursor extrapolator run failed"
  run_cmd bash "$install_root/setup/healthcheck.sh" --json \
    || optional_failure "Cursor package healthcheck failed"
}

seed_claude_model() {
  local install_root="$CLAUDE_HOME/current"
  [[ -d "$install_root" ]] || return 0
  log "Claude package: intent export and health check"
  run_cmd node "$install_root/service/claude_code_extrapolator.mjs" --config "$CLAUDE_CONFIG" --json \
    || optional_failure "Claude package extrapolator run failed"
  run_cmd bash "$install_root/setup/healthcheck.sh" --json \
    || optional_failure "Claude package healthcheck failed"
}

run_intent_injection() {
  if [[ "$SKIP_INTENT" -eq 1 ]]; then
    return 0
  fi

  local intent_json
  intent_json="$(python3 "$SUPPORTED_AGENT_HELPER" list-intent)" || {
    optional_failure "Could not list intent-capable agents from registry"
    return 0
  }

  local count
  count="$(printf '%s' "$intent_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
  if [[ "$count" -eq 0 ]]; then
    warn "No intent-capable agents found in registry"
    return 0
  fi

  log "Intent injection: ${count} agent(s)"

  local agent_type display_name intent_script timeout_secs
  while IFS=$'\t' read -r agent_type display_name intent_script timeout_secs; do
    [[ -n "$agent_type" ]] || continue
    if [[ ! -f "$intent_script" ]]; then
      optional_failure "Intent script not found for ${agent_type}: ${intent_script}"
      continue
    fi
    local effective_timeout="${timeout_secs:-$INTENT_TIMEOUT}"
    if [[ "$effective_timeout" -gt "$INTENT_TIMEOUT" ]]; then
      effective_timeout="$INTENT_TIMEOUT"
    fi
    log "Intent injection: ${display_name} (${agent_type}, timeout=${effective_timeout}s)"
    export E2E_POLL_ATTEMPTS=24
    export E2E_POLL_INTERVAL_SECS=5
    export E2E_SKIP_PROVISION_STRICT=1
    run_timeout "$effective_timeout" bash "$intent_script" \
      || optional_failure "Intent injection failed for ${agent_type}"
  done < <(printf '%s' "$intent_json" | python3 -c '
import json, sys
for a in json.load(sys.stdin):
    print("\t".join([a["agent_type"], a["display_name"], a["intent_script"], str(a["intent_timeout_seconds"])]))
')
}

run_cursor_snapshot() {
  local install_root="$CURSOR_HOME/current"
  [[ -d "$install_root" ]] || return 0
  log "Cursor package snapshot"
  run_cmd node "$install_root/service/verdict_reader.mjs" --config "$CURSOR_CONFIG" --json \
    || optional_failure "Cursor verdict reader failed"
}

run_claude_snapshot() {
  local install_root="$CLAUDE_HOME/current"
  [[ -d "$install_root" ]] || return 0
  log "Claude package snapshot"
  run_cmd node "$install_root/service/verdict_reader.mjs" --config "$CLAUDE_CONFIG" --json \
    || optional_failure "Claude verdict reader failed"
}

run_claude_agent_prompt() {
  local label="$1"
  local prompt="$2"
  if [[ "$SKIP_AGENTS" -eq 1 ]]; then
    return 0
  fi
  if ! have_command claude; then
    optional_failure "claude CLI not found; skipping Claude agent prompt: $label"
    return 0
  fi
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    optional_failure "ANTHROPIC_API_KEY is not set; skipping Claude agent prompt: $label"
    return 0
  fi
  log "Claude agent: $label"
  run_timeout 240 claude --plugin-dir "$CLAUDE_REPO" -p --dangerously-skip-permissions "$prompt" \
    || optional_failure "Claude agent prompt failed: $label"
}

run_openclaw_agent_prompt() {
  local label="$1"
  local message="$2"
  if [[ "$SKIP_AGENTS" -eq 1 ]]; then
    return 0
  fi
  if ! have_command openclaw; then
    optional_failure "openclaw CLI not found; skipping OpenClaw agent prompt: $label"
    return 0
  fi
  log "OpenClaw agent: $label"
  run_timeout 240 openclaw agent --local --agent main -m "$message" \
    || optional_failure "OpenClaw agent prompt failed: $label"
}

find_edamame_cli_bin() {
  local candidate
  for candidate in \
    "${EDAMAME_CLI_BIN:-}" \
    "${EDAMAME_CLI:-}" \
    "$CLI_REPO/target/release/edamame_cli" \
    "$CLI_REPO/target/release/edamame-cli" \
    "$CLI_REPO/target/debug/edamame_cli" \
    "$CLI_REPO/target/debug/edamame-cli"
  do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if have_command edamame_cli; then
    command -v edamame_cli
    return 0
  fi
  if have_command edamame-cli; then
    command -v edamame-cli
    return 0
  fi
  return 1
}

resolve_edamame_cli_bin() {
  if [[ -n "$EDAMAME_CLI_BIN_CACHE" ]]; then
    printf '%s\n' "$EDAMAME_CLI_BIN_CACHE"
    return 0
  fi

  if EDAMAME_CLI_BIN_CACHE="$(find_edamame_cli_bin)"; then
    printf '%s\n' "$EDAMAME_CLI_BIN_CACHE"
    return 0
  fi

  die "edamame_cli binary not found. Build/install it first or pass --skip-edamame-cli."
}

edamame_cli_json() {
  local method="$1"
  shift
  local cli_bin
  cli_bin="$(resolve_edamame_cli_bin)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "{}"
    return 0
  fi

  if [[ $# -gt 0 ]]; then
    "$cli_bin" rpc "$method" "$@" --pretty
  else
    "$cli_bin" rpc "$method" --pretty
  fi
}

json_count_entries() {
  local mode="${1:-generic}"
  python3 -c '
import json, sys
mode = sys.argv[1]
data = json.load(sys.stdin)
def generic_count(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("sessions","items","results","entries","todos","todo_list","active","data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return len(nested)
        return len(value)
    return 0
if mode == "score_active":
    print(len(data["active"]) if isinstance(data, dict) and isinstance(data.get("active"), list) else 0)
else:
    print(generic_count(data))
' "$mode"
}

json_extract_verdict() {
  python3 -c '
import json, sys
data = json.load(sys.stdin)
def unwrap(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value
def extract(value):
    value = unwrap(value)
    if isinstance(value, dict):
        for key in ("verdict","status","classification","result"):
            nested = value.get(key)
            if isinstance(nested, str):
                return nested
            if isinstance(nested, dict):
                inner = extract(nested)
                if inner:
                    return inner
    if isinstance(value, str):
        return value
    return "unknown"
print(extract(data))
'
}

capture_edamame_baseline() {
  local label="$1"
  local blacklisted_json anomalous_json score_json todos_json verdict_json

  if [[ "$SKIP_EDAMAME_CLI" -eq 1 ]]; then
    return 0
  fi

  blacklisted_json="$(edamame_cli_json get_blacklisted_sessions)" || die "edamame_cli get_blacklisted_sessions failed while capturing baseline"
  anomalous_json="$(edamame_cli_json get_anomalous_sessions)" || die "edamame_cli get_anomalous_sessions failed while capturing baseline"
  score_json="$(edamame_cli_json get_score '[false]')" || die "edamame_cli get_score failed while capturing baseline"
  todos_json="$(edamame_cli_json get_advisor)" || die "edamame_cli get_advisor failed while capturing baseline"
  verdict_json="$(edamame_cli_json get_divergence_verdict)" || die "edamame_cli get_divergence_verdict failed while capturing baseline"

  EDAMAME_BASELINE_BLACKLISTED="$(printf '%s' "$blacklisted_json" | json_count_entries)"
  EDAMAME_BASELINE_ANOMALOUS="$(printf '%s' "$anomalous_json" | json_count_entries)"
  EDAMAME_BASELINE_ACTIVE_THREATS="$(printf '%s' "$score_json" | json_count_entries score_active)"
  EDAMAME_BASELINE_TODOS="$(printf '%s' "$todos_json" | json_count_entries)"
  EDAMAME_BASELINE_VERDICT="$(printf '%s' "$verdict_json" | json_extract_verdict)"
  EDAMAME_BASELINE_CAPTURED=1

  log "EDAMAME CLI baseline (${label}): blacklisted=${EDAMAME_BASELINE_BLACKLISTED} anomalous=${EDAMAME_BASELINE_ANOMALOUS} active_threats=${EDAMAME_BASELINE_ACTIVE_THREATS} todos=${EDAMAME_BASELINE_TODOS} verdict=${EDAMAME_BASELINE_VERDICT}"
}

wait_for_edamame_recovery() {
  local scenario="$1"
  local deadline blacklisted_json anomalous_json score_json todos_json verdict_json
  local blacklisted_count anomalous_count active_threats_count todos_count verdict recovered

  if [[ "$SKIP_EDAMAME_CLI" -eq 1 || "$EDAMAME_BASELINE_CAPTURED" -eq 0 ]]; then
    return 0
  fi

  deadline=$((SECONDS + VERIFY_TIMEOUT))

  while true; do
    blacklisted_json="$(edamame_cli_json get_blacklisted_sessions)" || die "edamame_cli get_blacklisted_sessions failed during recovery verification"
    anomalous_json="$(edamame_cli_json get_anomalous_sessions)" || die "edamame_cli get_anomalous_sessions failed during recovery verification"
    score_json="$(edamame_cli_json get_score '[false]')" || die "edamame_cli get_score failed during recovery verification"
    todos_json="$(edamame_cli_json get_advisor)" || die "edamame_cli get_advisor failed during recovery verification"
    verdict_json="$(edamame_cli_json get_divergence_verdict)" || die "edamame_cli get_divergence_verdict failed during recovery verification"

    blacklisted_count="$(printf '%s' "$blacklisted_json" | json_count_entries)"
    anomalous_count="$(printf '%s' "$anomalous_json" | json_count_entries)"
    active_threats_count="$(printf '%s' "$score_json" | json_count_entries score_active)"
    todos_count="$(printf '%s' "$todos_json" | json_count_entries)"
    verdict="$(printf '%s' "$verdict_json" | json_extract_verdict)"

    log "EDAMAME CLI verify (${scenario}): blacklisted=${blacklisted_count}/${EDAMAME_BASELINE_BLACKLISTED} anomalous=${anomalous_count}/${EDAMAME_BASELINE_ANOMALOUS} active_threats=${active_threats_count}/${EDAMAME_BASELINE_ACTIVE_THREATS} todos=${todos_count}/${EDAMAME_BASELINE_TODOS} verdict=${verdict}"

    recovered=1
    [[ "$blacklisted_count" -le "$EDAMAME_BASELINE_BLACKLISTED" ]] || recovered=0
    [[ "$anomalous_count" -le "$EDAMAME_BASELINE_ANOMALOUS" ]] || recovered=0
    [[ "$active_threats_count" -le "$EDAMAME_BASELINE_ACTIVE_THREATS" ]] || recovered=0

    if [[ "$recovered" -eq 1 ]]; then
      log "EDAMAME CLI recovery verified for ${scenario}"
      return 0
    fi

    if (( SECONDS >= deadline )); then
      optional_failure "EDAMAME CLI recovery check for ${scenario} did not return to baseline within ${VERIFY_TIMEOUT}s; lingering CVE alerts/sessions may still be active"
      return 0
    fi

    run_cmd sleep "$VERIFY_INTERVAL"
  done
}

run_edamame_cli_snapshot() {
  local cli_bin
  if [[ "$SKIP_EDAMAME_CLI" -eq 1 ]]; then
    return 0
  fi
  cli_bin="$(resolve_edamame_cli_bin)"
  log "Direct EDAMAME CLI snapshot"
  run_cmd "$cli_bin" rpc get_score '[false]' --pretty || optional_failure "edamame_cli get_score failed"
  run_cmd "$cli_bin" rpc get_divergence_verdict --pretty || optional_failure "edamame_cli get_divergence_verdict failed"
  run_cmd "$cli_bin" rpc get_advisor --pretty || optional_failure "edamame_cli get_advisor failed"
  run_cmd "$cli_bin" rpc get_anomalous_sessions --pretty || optional_failure "edamame_cli get_anomalous_sessions failed"
  run_cmd "$cli_bin" rpc get_blacklisted_sessions --pretty || optional_failure "edamame_cli get_blacklisted_sessions failed"
}

run_injector() {
  local scenario="$1"
  local duration="$2"
  local script_path="$TRIGGERS_DIR/trigger_${scenario}.py"

  [[ -f "$script_path" ]] || die "Injector script not found: $script_path"

  log "Running injector ${scenario} (agent-type=${AGENT_TYPE})"
  run_timeout "$((duration + 30))" python3 "$script_path" --agent-type "$AGENT_TYPE" --duration "$duration" \
    || optional_failure "Injector failed: $scenario"
}

run_injector_cleanup() {
  local cleanup_path="$TRIGGERS_DIR/cleanup.py"
  [[ -f "$cleanup_path" ]] || return 0
  log "Cleaning up injector state for ${AGENT_TYPE}"
  run_cmd python3 "$cleanup_path" --agent-type "$AGENT_TYPE" || optional_failure "Injector cleanup failed for ${AGENT_TYPE}"
}

baseline_round() {
  run_openclaw_agent_prompt \
    "posture baseline" \
    "Use the edamame-posture skill. Show the current score, active advisor todos, recent sessions, and the divergence verdict. Keep the result concise and structured."

  run_claude_agent_prompt \
    "plugin baseline" \
    "Use the EDAMAME plugin tools to run a health and posture baseline. Summarize score, active todos, and divergence status as short JSON."

  run_cursor_snapshot
  run_claude_snapshot
  run_edamame_cli_snapshot
}

seed_models_with_agent_activity() {
  run_openclaw_agent_prompt \
    "extrapolator seed" \
    "Use the edamame-extrapolator skill. Always try compiled mode first, run one extrapolator cycle, then confirm whether a behavioral model exists for this OpenClaw deployment."

  run_claude_agent_prompt \
    "intent export seed" \
    "Use the EDAMAME plugin to export the latest Claude Code intent if needed, then summarize the behavioral model and divergence engine state."

  seed_cursor_model
  seed_claude_model
}

post_scenario_readout() {
  local scenario="$1"
  run_openclaw_agent_prompt \
    "${scenario} readout" \
    "Use the edamame-posture skill. Inspect the current divergence verdict, anomalous sessions, blacklisted sessions, and active advisor todos after the latest demo activity. Keep the response short and structured."

  run_claude_agent_prompt \
    "${scenario} readout" \
    "Use the EDAMAME plugin tools to summarize the current divergence verdict, anomalous sessions, blacklisted sessions, and active todos after the latest demo activity. Return compact JSON."

  run_cursor_snapshot
  run_claude_snapshot
  run_edamame_cli_snapshot
}

needs_behavioral_models() {
  [[ "$FOCUS" == "divergence" || "$FOCUS" == "all" ]]
}

run_demo_loop() {
  local iteration scenario duration
  log "Demo focus: ${FOCUS} (${#SCENARIOS[@]} scenarios)"
  for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
    log "Starting demo iteration ${iteration}/${ITERATIONS}"
    baseline_round

    if needs_behavioral_models; then
      seed_models_with_agent_activity
      run_intent_injection
    else
      log "Skipping behavioral model seeding (vuln-only mode)"
    fi

    for scenario in "${SCENARIOS[@]}"; do
      case "$scenario" in
        divergence|goal_drift) duration="$DIVERGENCE_DURATION" ;;
        *) duration="$SCENARIO_DURATION" ;;
      esac

      capture_edamame_baseline "before_${scenario}"

      if [[ "$scenario" == "file_events" ]]; then
        python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_file_events >/dev/null 2>&1 || true
        python3 "$TRIGGERS_DIR/_edamame_cli.py" start_file_monitor '[[]]' >/dev/null 2>&1 || true
        log "Started FIM for file_events scenario"
      fi

      run_injector_cleanup
      run_injector "$scenario" "$duration"

      if [[ "$POST_WAIT" -gt 0 ]]; then
        log "Waiting ${POST_WAIT}s for EDAMAME to ingest scenario ${scenario}"
        run_cmd sleep "$POST_WAIT"
      fi

      post_scenario_readout "$scenario"
      run_injector_cleanup

      if [[ "$scenario" == "file_events" ]]; then
        python3 "$TRIGGERS_DIR/_edamame_cli.py" stop_file_monitor >/dev/null 2>&1 || true
        log "Stopped FIM after file_events scenario"
      fi

      wait_for_edamame_recovery "$scenario"

      if [[ "$COOLDOWN" -gt 0 ]]; then
        log "Cooling down for ${COOLDOWN}s"
        run_cmd sleep "$COOLDOWN"
      fi
    done
  done
}

summarize_next_steps() {
  cat <<EOF

Demo orchestration complete.

Backup directory:
  $BACKUP_ROOT

Key local assets refreshed:
  Cursor config:   $CURSOR_CONFIG
  Cursor MCP file: $CURSOR_MCP_TARGET
  Claude config:   $CLAUDE_CONFIG
  OpenClaw token:  $OPENCLAW_PSK

Recommended follow-up:
  - Inspect the EDAMAME app UI for score, sessions, threats, and divergence verdict changes.
  - If you want Cursor itself to pick up the refreshed MCP snippet immediately, restart Cursor.
  - If you want Claude Code desktop to use the staged config outside this script, merge the rendered
    snippet from: $CLAUDE_HOME/claude-code-mcp.json
EOF
}

main() {
  validate_inputs
  check_prereqs
  ensure_edamame_app

  log "Workspace root: $WORKSPACE_ROOT"
  log "Agent type: $AGENT_TYPE"
  log "Focus mode: $FOCUS"

  if [[ "$SKIP_PROVISION" -eq 0 ]]; then
    install_cursor_package
    install_claude_package
    install_openclaw_surface
  else
    warn "Skipping provisioning by request"
  fi

  ensure_pairing

  if [[ -f "$OPENCLAW_PSK" ]]; then
    sync_all_psks
  fi

  if [[ "$PROVISION_ONLY" -eq 1 ]]; then
    summarize_next_steps
    return 0
  fi

  run_demo_loop
  summarize_next_steps
}

main "$@"
