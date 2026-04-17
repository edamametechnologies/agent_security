#!/usr/bin/env bash
#
# Long-run harness: agent-integration intent E2E scripts (Claude / OpenClaw / Cursor),
# optional CVE-style demo injectors, behavioral-model merge snapshots, and structured reports.
#
# Complements run_agent_security_demo.sh (full demo loop). This harness focuses on
# repeatable verification and merge visibility without re-provisioning packages.
#
# Runs on macOS, Linux, and Windows (under Git Bash / WSL); paths follow
# run_agent_security_demo.sh. macOS remains the primary validation target.
# Requires EDAMAME app + MCP, edamame_cli, python3, bash 4+.
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_agent_security_e2e_harness.sh [options]

Options:
  --workspace-root PATH       Workspace for package configs (default: this repo).
  --duration-seconds N          Wall-clock budget; stops before starting a new round
                              when exceeded. Default: 7200 (2 hours).
  --round-interval-seconds N    Sleep after each full round. Default: 0.
  --stop-after-clean-round     Stop after the first round with no intent/CVE failures (default).
  --loop-rounds                Continue into round 2+ until duration budget or failure.
  --focus MODE                intent | cve | both (default: intent).
                              intent: registry-driven agent intent scripts from supported_agents/index.json
                              cve:    demo injectors (9 scenarios: blacklist, CVE, divergence, memory-poisoning, goal-drift, credential-sprawl, tool-poisoning, supply-chain-exfil)
                              both:   intent suite then CVE suite each round (often >30 min per round;
                                      shorten with --scenario-duration / --divergence-duration).
  --parallel-intent           Run the intent scripts concurrently (faster, heavier LLM).
  --sequential-intent         Default: run intent scripts one after another.
  --agent-type NAME           Agent type for triggers; validated against the supported-agent registry. Default: openclaw.
  --scenario-duration SEC     CVE injector duration (non-divergence). Default: 150.
                              Must be >= 120s for L7 open_files attribution on macOS.
  --divergence-duration SEC     divergence injector duration. Default: 90.
  --post-wait SEC             Wait after each injector before cleanup. Default: 15.
  --cve-cooldown SEC          Pause between CVE scenarios. Default: 8.
  --skip-intent               Skip intent injection legs (which require
                              EDAMAME_LLM_API_KEY / live LLM access).
                              CVE injector legs still run if --focus includes cve.
  --strict                    Exit on first intent E2E or injector failure.
  --continue-on-failure       Default: record failures and continue rounds.
  --intent-poll-attempts N    Passed as E2E_POLL_ATTEMPTS to intent scripts (default: 48).
  --report-dir PATH           Default: ~/.edamame_e2e_reports/<timestamp>/
  --dry-run                   Print planned actions only.
  -h, --help                  This help.

Environment (passed through to child scripts):
  EDAMAME_CLI, E2E_*, CURSOR_EDAMAME_CONFIG, CLAUDE_CODE_EDAMAME_CONFIG,
  E2E_OPENCLAW_AGENT_INSTANCE_ID (optional; harness sets e2e-harness-<RUN_TS> if unset),
  E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID (optional; default: e2e-divergence-harness-<RUN_TS>),
  DIVERGENCE_MODEL_MIN_AGE_SECS (optional; default: 65),
  Registry repo overrides (for example CURSOR_REPO / CLAUDE_REPO / CLAUDE_DESKTOP_REPO / OPENCLAW_REPO),
  E2E_SKIP_PLUGIN_CHECK, E2E_SKIP_PROVISION_STRICT (Cursor/Claude intent legs),
  E2E_SKIP_REPO_VERSION_CHECK (OpenClaw intent leg), etc.

Reports:
  - report.jsonl   one JSON object per round (and per merge snapshot)
  - SUMMARY.md     human-readable rollup when the harness exits (or is stopped)

Merge analysis:
  Each round records contributor slices (agent_type, agent_instance_id, hash) and
  prediction counts grouped by producer. A healthy multi-agent setup shows multiple
  contributors and non-zero predictions per agent_type after intent pushes.

Per-intent diagnostics:
  Each leg writes round_<n>_<claude_code|claude_desktop|openclaw|cursor>.log, *_diag.json on failure
  (JSON: missing session_keys, contributor list, prediction counts). Round rows in
  report.jsonl include intent_legs with exit codes and durations.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIGGERS_DIR="$ROOT_DIR/triggers"
SUPPORTED_AGENT_HELPER="$ROOT_DIR/supported_agents.py"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$ROOT_DIR/../../..}"
DURATION_SECONDS=7200
ROUND_INTERVAL_SECONDS=0
FOCUS="intent"
PARALLEL_INTENT=0
AGENT_TYPE="openclaw"
SCENARIO_DURATION=150
DIVERGENCE_DURATION=90
POST_WAIT=15
CVE_COOLDOWN=8
STRICT=0
CONTINUE_ON_FAILURE=1
DRY_RUN=0
REPORT_DIR=""
INTENT_POLL_ATTEMPTS=48
STOP_AFTER_CLEAN_ROUND=1
SKIP_INTENT=0
DIVERGENCE_MODEL_MIN_AGE_SECS="${DIVERGENCE_MODEL_MIN_AGE_SECS:-65}"

CLI_REPO="${EDAMAME_CLI_REPO:-$ROOT_DIR/../../../edamame_cli}"
INTENT_AGENTS_JSON="[]"
SUPPORTED_AGENT_TYPES_JSON="[]"

RUN_TS="$(date +"%Y%m%d-%H%M%S")"
HARNESS_START_EPOCH="$(date +%s)"
ROUND_INDEX=0
ANY_FAILURE=0
CAPTURE_STARTED_BY_HARNESS=0
VERIFY_BASELINE_VULN_TOTAL=0

while (($# > 0)); do
  case "$1" in
    --workspace-root) WORKSPACE_ROOT="$2"; shift 2 ;;
    --duration-seconds) DURATION_SECONDS="$2"; shift 2 ;;
    --round-interval-seconds) ROUND_INTERVAL_SECONDS="$2"; shift 2 ;;
    --focus)
      FOCUS="$2"
      shift 2
      ;;
    --parallel-intent) PARALLEL_INTENT=1; shift ;;
    --sequential-intent) PARALLEL_INTENT=0; shift ;;
    --agent-type) AGENT_TYPE="$2"; shift 2 ;;
    --scenario-duration) SCENARIO_DURATION="$2"; shift 2 ;;
    --divergence-duration) DIVERGENCE_DURATION="$2"; shift 2 ;;
    --post-wait) POST_WAIT="$2"; shift 2 ;;
    --cve-cooldown) CVE_COOLDOWN="$2"; shift 2 ;;
    --strict)
      STRICT=1
      CONTINUE_ON_FAILURE=0
      shift
      ;;
    --continue-on-failure) CONTINUE_ON_FAILURE=1; STRICT=0; shift ;;
    --intent-poll-attempts) INTENT_POLL_ATTEMPTS="$2"; shift 2 ;;
    --stop-after-clean-round) STOP_AFTER_CLEAN_ROUND=1; shift ;;
    --loop-rounds) STOP_AFTER_CLEAN_ROUND=0; shift ;;
    --report-dir)
      REPORT_DIR="$2"
      shift 2
      ;;
    --skip-intent) SKIP_INTENT=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
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

case "$FOCUS" in
  intent|cve|both) ;;
  *)
    echo "--focus must be intent, cve, or both" >&2
    exit 1
    ;;
esac

if [[ -z "$REPORT_DIR" ]]; then
  REPORT_DIR="${HOME}/.edamame_e2e_reports/${RUN_TS}"
fi

mkdir -p "$REPORT_DIR"
REPORT_JSONL="$REPORT_DIR/report.jsonl"
SUMMARY_MD="$REPORT_DIR/SUMMARY.md"

log() { printf '[%s] %s\n' "$(date +"%H:%M:%S")" "$*" | tee -a "$REPORT_DIR/console.log"; }
warn() { printf '[%s] WARNING: %s\n' "$(date +"%H:%M:%S")" "$*" | tee -a "$REPORT_DIR/console.log" >&2; }

die() {
  printf '[%s] ERROR: %s\n' "$(date +"%H:%M:%S")" "$*" | tee -a "$REPORT_DIR/console.log" >&2
  exit 1
}

have_command() { command -v "$1" >/dev/null 2>&1; }

require_command() {
  have_command "$1" || die "Required command not found: $1"
}

emit_intent_agent_lines() {
  python3 - "$INTENT_AGENTS_JSON" <<'PY'
import json
import sys

for agent in json.loads(sys.argv[1]):
    print(
        "\t".join(
            [
                agent["agent_type"],
                agent["display_name"],
                agent["intent_script"],
                str(agent["intent_timeout_seconds"]),
            ]
        )
    )
PY
}

validate_supported_agent_type() {
  local agent_type="$1"
  python3 - "$SUPPORTED_AGENT_TYPES_JSON" "$agent_type" <<'PY'
import json
import sys

supported = set(json.loads(sys.argv[1]))
agent_type = sys.argv[2]
if agent_type not in supported:
    print(
        f"--agent-type must be one of: {', '.join(sorted(supported))}",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
}

budget_exhausted() {
  local now elapsed
  now="$(date +%s)"
  elapsed=$((now - HARNESS_START_EPOCH))
  ((elapsed >= DURATION_SECONDS))
}

find_edamame_cli_bin() {
  local candidate
  for candidate in \
    "${EDAMAME_CLI_BIN:-}" \
    "${EDAMAME_CLI:-}" \
    "$CLI_REPO/target/release/edamame_cli" \
    "$CLI_REPO/target/release/edamame-cli" \
    "$CLI_REPO/target/debug/edamame_cli" \
    "$CLI_REPO/target/debug/edamame-cli"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if have_command edamame_cli; then command -v edamame_cli; return 0; fi
  if have_command edamame-cli; then command -v edamame-cli; return 0; fi
  return 1
}

ensure_edamame_app() {
  if [[ "$DRY_RUN" -eq 1 ]]; then return 0; fi
  local port="${EDAMAME_MCP_PORT:-3000}"
  local health
  health="$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null || true)"
  [[ "$health" == "OK" ]] || die "EDAMAME MCP health check failed on port ${port}. Start the app or edamame_posture with MCP enabled (set EDAMAME_MCP_PORT to override)."
}

capture_running_flag() {
  python3 -c "
import sys
sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
print('1' if cli_rpc('is_capturing') else '0')
" 2>/dev/null || echo "0"
}

ensure_capture_running() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Capture preflight: [DRY-RUN] ensure capture running"
    return 0
  fi

  local cli_bin running attempt
  cli_bin="$(find_edamame_cli_bin)" || die "edamame_cli not found for capture preflight"
  running="$(capture_running_flag)"
  if [[ "$running" == "1" ]]; then
    log "Capture preflight: capture already running"
    return 0
  fi

  log "Capture preflight: starting packet capture"
  "$cli_bin" rpc start_capture >/dev/null 2>&1 || die "Failed to start packet capture via edamame_cli"

  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    running="$(capture_running_flag)"
    if [[ "$running" == "1" ]]; then
      CAPTURE_STARTED_BY_HARNESS=1
      log "Capture preflight: capture is running"
      return 0
    fi
    run_cmd sleep 2
  done

  die "Packet capture did not become active after start_capture"
}

# kill_by_pattern terminates matching processes. Uses pkill on Unix-like hosts
# (macOS, Linux, WSL, Git Bash when procps is installed). Falls back to
# taskkill via a Python shim on native Windows where pkill is absent.
kill_by_pattern() {
  local pattern="$1"
  if command -v pkill >/dev/null 2>&1; then
    pkill -f "$pattern" 2>/dev/null || true
    return 0
  fi
  python3 - "$pattern" <<'PY' 2>/dev/null || true
import subprocess
import sys

pattern = sys.argv[1]
if sys.platform == "win32":
    subprocess.run(
        ["taskkill", "/F", "/FI", f"IMAGENAME eq {pattern}*"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
PY
}

restore_capture_state() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  log "Harness teardown: killing leaked probe processes"
  kill_by_pattern sandbox_probe
  kill_by_pattern divergence_probe

  log "Harness teardown: running injector cleanup for all agent types"
  local cleanup_path="$TRIGGERS_DIR/cleanup.py"
  if [[ -f "$cleanup_path" ]]; then
    for at in openclaw cursor claude_code claude_desktop; do
      python3 "$cleanup_path" --agent-type "$at" 2>/dev/null || true
    done
  fi

  log "Harness teardown: clearing vulnerability history"
  local cli_bin
  if cli_bin="$(find_edamame_cli_bin 2>/dev/null)"; then
    "$cli_bin" rpc clear_vulnerability_history >/dev/null 2>&1 || true
  fi

  if [[ "$CAPTURE_STARTED_BY_HARNESS" -ne 1 ]]; then
    return 0
  fi

  log "Harness teardown: stopping packet capture started by harness"
  if ! cli_bin="$(find_edamame_cli_bin)"; then
    warn "Could not restore capture state: edamame_cli not found"
    return 0
  fi

  if ! "$cli_bin" rpc stop_capture >/dev/null 2>&1; then
    warn "Failed to stop packet capture started by harness"
    return 0
  fi

  local running
  running="$(capture_running_flag)"
  if [[ "$running" == "1" ]]; then
    warn "Packet capture still reports running after stop_capture"
  fi
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
    printf '+ timeout=%s ' "$timeout_secs"
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  python3 - "$timeout_secs" "$@" <<'PY'
import subprocess
import sys
timeout = float(sys.argv[1])
cmd = sys.argv[2:]
try:
    raise SystemExit(subprocess.run(cmd, timeout=timeout).returncode)
except subprocess.TimeoutExpired:
    print(f"Timed out after {timeout:.0f}s: {' '.join(cmd)}", file=sys.stderr)
    raise SystemExit(124)
PY
}

append_jsonl() {
  if [[ "$DRY_RUN" -eq 1 ]]; then return 0; fi
  printf '%s\n' "$1" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), ensure_ascii=False))" >>"$REPORT_JSONL"
}

run_injector() {
  local scenario="$1"
  local duration="$2"
  local script_path="$TRIGGERS_DIR/trigger_${scenario}.py"
  [[ -f "$script_path" ]] || die "Injector not found: $script_path"
  log "CVE injector: $scenario (${duration}s, agent-type=${AGENT_TYPE})"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run_timeout "$((duration + 45))" python3 "$script_path" --agent-type "$AGENT_TYPE" --duration "$duration"
    return $?
  fi
  python3 "$script_path" --agent-type "$AGENT_TYPE" --duration "$duration" &
  INJECTOR_PID=$!
  log "  injector pid=$INJECTOR_PID (background)"
}

stop_injector() {
  if [[ -n "${INJECTOR_PID:-}" ]] && kill -0 "$INJECTOR_PID" 2>/dev/null; then
    log "  stopping injector pid=$INJECTOR_PID"
    kill "$INJECTOR_PID" 2>/dev/null || true
    wait "$INJECTOR_PID" 2>/dev/null || true
  fi
  INJECTOR_PID=""
}

run_injector_cleanup() {
  local cleanup_path="$TRIGGERS_DIR/cleanup.py"
  [[ -f "$cleanup_path" ]] || return 0
  log "Injector cleanup (${AGENT_TYPE})"
  run_cmd python3 "$cleanup_path" --agent-type "$AGENT_TYPE" || true
}

ensure_divergence_harness_ready() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Divergence harness: [DRY-RUN] start engine + seed probe-scoped model"
    return 0
  fi

  local cli_bin
  cli_bin="$(find_edamame_cli_bin)" || die "edamame_cli not found for divergence harness setup"

  if [[ -z "${E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID:-}" ]]; then
    export E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID="e2e-divergence-harness-${RUN_TS}"
  fi

  log "Divergence harness: seeding probe-scoped model (agent_type=${AGENT_TYPE}, agent_instance_id=${E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID})"
  local status_json
  local status_file
  status_file="$(mktemp "${TMPDIR:-/tmp}/edamame_divergence_status.XXXXXX")"
  if ! \
    EDAMAME_CLI_BIN="$cli_bin" \
    AGENT_TYPE="$AGENT_TYPE" \
    E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID="$E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID" \
    python3 <<'PY' >"$status_file"
import datetime
import json
import os
import subprocess

cli = os.environ["EDAMAME_CLI_BIN"]
agent_type = os.environ["AGENT_TYPE"]
agent_instance_id = os.environ["E2E_DIVERGENCE_HARNESS_AGENT_INSTANCE_ID"]


def parse_cli_output(raw: str):
    text = raw.strip()
    if text.startswith("Result: "):
        text = text[len("Result: "):]
    parsed = json.loads(text)
    if isinstance(parsed, str):
        return json.loads(parsed)
    return parsed


def rpc(method: str, args: str | None = None):
    cmd = [cli, "rpc", method]
    if args is not None:
        cmd.append(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or f"rpc {method} failed")
    return parse_cli_output(result.stdout)


rpc("start_divergence_engine", "[true, 300]")

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
blocked_traffic = [f"one.one.one.one:{port}" for port in range(63169, 63177)]
blocked_traffic += [f"1.0.0.1:{port}" for port in range(63169, 63177)]
blocked_traffic += [f"one.one.one.one:{port}" for port in range(63200, 63215)]
blocked_traffic += [f"1.1.1.1:{port}" for port in range(63200, 63215)]
window = {
    "window_start": (now - datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    "window_end": (now - datetime.timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
    "agent_type": agent_type,
    "agent_instance_id": agent_instance_id,
    "predictions": [
        {
            "agent_type": agent_type,
            "agent_instance_id": agent_instance_id,
            "session_key": "e2e_divergence_probe_scope",
            "action": "Harness divergence probe scope",
            "tools_called": ["run"],
            "scope_process_paths": ["*/divergence_probe"],
            "scope_parent_paths": [],
            "scope_grandparent_paths": [],
            "scope_any_lineage_paths": [],
            "expected_traffic": ["api.anthropic.com:443"],
            "expected_sensitive_files": [],
            "expected_lan_devices": [],
            "expected_local_open_ports": [],
            "expected_process_paths": ["*/divergence_probe"],
            "expected_parent_paths": [],
            "expected_grandparent_paths": [],
            "expected_open_files": [],
            "expected_l7_protocols": [],
            "expected_system_config": [],
            "not_expected_traffic": blocked_traffic,
            "not_expected_sensitive_files": [],
            "not_expected_lan_devices": [],
            "not_expected_local_open_ports": [],
            "not_expected_process_paths": [],
            "not_expected_parent_paths": [],
            "not_expected_grandparent_paths": [],
            "not_expected_open_files": [],
            "not_expected_l7_protocols": [],
            "not_expected_system_config": [],
            "raw_input": None,
        }
    ],
    "contributors": [],
    "version": "e2e/divergence-probe",
    "hash": "",
    "ingested_at": now.isoformat().replace("+00:00", "Z"),
}

subprocess.run(
    [cli, "rpc", "upsert_behavioral_model", json.dumps({"window_json": json.dumps(window)})],
    check=True,
    capture_output=True,
    text=True,
)
status = rpc("get_divergence_engine_status")
print(
    json.dumps(
        {
            "running": bool(status.get("running")),
            "contributor_count": int(status.get("contributor_count") or 0),
            "model_age_secs": int(status.get("model_age_secs") or 0),
            "agent_instance_id": agent_instance_id,
        }
    )
)
PY
  then
    rm -f "$status_file"
    return 1
  fi
  status_json="$(<"$status_file")"
  rm -f "$status_file"
  log "  divergence engine status: $status_json"
}

wait_for_divergence_model_ready() {
  if [[ "$DRY_RUN" -eq 1 ]]; then return 0; fi

  local waited=0
  local max_wait=$((DIVERGENCE_MODEL_MIN_AGE_SECS * 4))
  while ((waited <= max_wait)); do
    local status
    status="$(python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
s = cli_rpc('get_divergence_engine_status')
age = s.get('model_age_secs') if isinstance(s, dict) else 0
contrib = s.get('contributor_count') if isinstance(s, dict) else 0
running = bool(s.get('running')) if isinstance(s, dict) else False
print(f'{int(age or 0)}|{int(contrib or 0)}|{1 if running else 0}')
" 2>/dev/null || echo "0|0|0")"
    local age="${status%%|*}"
    local rest="${status#*|}"
    local contrib="${rest%%|*}"
    local running="${rest#*|}"
    if [[ "$running" -eq 1 && "$contrib" -gt 0 && "$age" -ge "$DIVERGENCE_MODEL_MIN_AGE_SECS" ]]; then
      return 0
    fi
    log "  divergence model warming: running=$running contributors=$contrib age=${age}s (need ${DIVERGENCE_MODEL_MIN_AGE_SECS}s)"
    run_cmd sleep 5
    waited=$((waited + 5))
  done

  warn "Divergence model did not reach ready age after ${max_wait}s"
  return 1
}

divergence_semantic_status_for_scenario() {
  local scenario="$1"
  TRIGGERS_PATH="$TRIGGERS_DIR" python3 - "$scenario" "$DIVERGENCE_MODEL_MIN_AGE_SECS" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_PATH"])
from _edamame_cli import cli_rpc

scenario = sys.argv[1].strip()
min_age = int(sys.argv[2])

expected_prefixes = {
    "divergence": ["1.0.0.1:", "one.one.one.one:"],
    "goal_drift": ["1.1.1.1:", "one.one.one.one:"],
}.get(scenario, [])

summary = cli_rpc("get_divergence_verdict")
status = cli_rpc("get_divergence_engine_status")
sessions = cli_rpc("get_current_sessions")

probe_active = 0
for session in sessions if isinstance(sessions, list) else []:
    if not isinstance(session, dict):
        continue
    l7 = session.get("l7") or {}
    process_path = str(l7.get("process_path") or "")
    active = bool((session.get("status") or {}).get("active"))
    path_normalized = process_path.replace("\\\\", "/")
    if path_normalized.endswith(".exe"):
        path_normalized = path_normalized[:-4]
    if path_normalized.endswith("/divergence_probe") and active:
        probe_active += 1

verdict = str(summary.get("verdict") or "").strip().upper()
decision_source = str(summary.get("decision_source") or "").strip()
trace_available = summary.get("trace_available")
entry_id = str(summary.get("entry_id") or "").strip()
evidence = summary.get("evidence") or []
categories = sorted(
    {
        str(item.get("category") or "").strip()
        for item in evidence
        if isinstance(item, dict) and str(item.get("category") or "").strip()
    }
)
descriptions = [
    str(item.get("description") or "")
    for item in evidence
    if isinstance(item, dict)
]

running = bool(status.get("running")) if isinstance(status, dict) else False
contributors = int(status.get("contributor_count") or 0) if isinstance(status, dict) else 0
age = int(status.get("model_age_secs") or 0) if isinstance(status, dict) else 0

category_ok = "correlation:not_expected" in categories
description_ok = True if not expected_prefixes else any(
    prefix in description
    for prefix in expected_prefixes
    for description in descriptions
)
trace_ok = isinstance(trace_available, bool) and (not trace_available or bool(entry_id))
decision_ok = bool(decision_source)

confirmed_decision = decision_source in (
    "LlmConfirmed", "Deterministic", "LlmOverride",
)
age_ok = age >= min_age or (verdict == "DIVERGENCE" and confirmed_decision)

ok = all(
    [
        verdict == "DIVERGENCE",
        probe_active > 0,
        running,
        contributors > 0,
        age_ok,
        category_ok,
        description_ok,
        trace_ok,
        decision_ok,
    ]
)

message = (
    "verdict={} probe_active={} model_age={}s contributors={} running={} "
    "decision_source={} trace_available={} categories={} entry_id={}"
).format(
    verdict or "NONE", probe_active, age, contributors, int(running),
    decision_source or "NONE", trace_available,
    ",".join(categories) if categories else "none",
    entry_id or "missing",
)
print(("OK" if ok else "WAIT") + "|" + message)
PYEOF
}

assert_divergence_verdict_state() {
  local label="$1"
  local expected_verdict="$2"
  local min_contributors="$3"
  local min_model_age="$4"

  local verdict_status
  verdict_status="$(TRIGGERS_PATH="$TRIGGERS_DIR" python3 - "$expected_verdict" "$min_contributors" "$min_model_age" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_PATH"])
from _edamame_cli import cli_rpc

expected = sys.argv[1].strip().upper()
min_contributors = int(sys.argv[2])
min_model_age = int(sys.argv[3])

summary = cli_rpc("get_divergence_verdict")
status = cli_rpc("get_divergence_engine_status")
history = cli_rpc("get_divergence_history", "[5]")
history = history if isinstance(history, list) else []

verdict = str(summary.get("verdict") or "").strip().upper()
entry_id = str(summary.get("entry_id") or "").strip()
trace_available = summary.get("trace_available")
running = bool(status.get("running")) if isinstance(status, dict) else False
contributors = int(status.get("contributor_count") or 0) if isinstance(status, dict) else 0
model_age = int(status.get("model_age_secs") or 0) if isinstance(status, dict) else 0

history_ids = set()
for h in history:
    if isinstance(h, dict):
        hid = str(h.get("entry_id") or "").strip()
        if hid:
            history_ids.add(hid)

entry_in_history = bool(entry_id) and entry_id in history_ids
age_ok = model_age >= min_model_age or verdict == expected

ok = all(
    [
        verdict == expected,
        bool(entry_id),
        running,
        contributors >= min_contributors,
        age_ok,
        entry_in_history,
        isinstance(trace_available, bool),
    ]
)

history_entry_id = ""
if history and isinstance(history[0], dict):
    history_entry_id = str(history[0].get("entry_id") or "").strip()

message = (
    "verdict={} entry_id={} running={} contributors={} age={}s "
    "trace_available={} entry_in_history={} history_entry_id={}"
).format(
    verdict or "NONE", entry_id or "missing", int(running), contributors,
    model_age, trace_available, int(entry_in_history),
    history_entry_id or "missing",
)
print(("OK" if ok else "FAIL") + "|" + message)
PYEOF
)"

  local status="${verdict_status%%|*}"
  local message="${verdict_status#*|}"
  if [[ "$status" == "OK" ]]; then
    log "  $label: $message"
    return 0
  fi

  warn "  $label failed: $message"
  return 1
}

run_divergence_engine_state_checks() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Divergence state suite: [DRY-RUN] no-model, clean, stale, dismissal, debug-trace"
    return 0
  fi

  log "Running divergence engine state suite"
  local rc=0

  TRIGGERS_PATH="$TRIGGERS_DIR" python3 - <<'PYEOF' >/dev/null 2>&1 || true
import os, sys
sys.path.insert(0, os.environ["TRIGGERS_PATH"])
from _edamame_cli import cli_rpc
cli_rpc("clear_divergence_state")
cli_rpc("clear_divergence_history")
cli_rpc("start_divergence_engine", "[true, 300]")
cli_rpc("clear_behavioral_model")
cli_rpc("debug_run_divergence_tick")
PYEOF

  if ! assert_divergence_verdict_state "NoModel state" "NOMODEL" 0 0; then
    rc=1
    if [[ "$STRICT" -eq 1 ]]; then
      return 1
    fi
  fi

  python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_divergence_state >/dev/null 2>&1 || true
  python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_divergence_history >/dev/null 2>&1 || true
  ensure_divergence_harness_ready || return 1
  wait_for_divergence_model_ready || return 1
  python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_divergence_tick >/dev/null 2>&1 || true
  if ! assert_divergence_verdict_state "Clean state" "CLEAN" 1 "$DIVERGENCE_MODEL_MIN_AGE_SECS"; then
    rc=1
    if [[ "$STRICT" -eq 1 ]]; then
      return 1
    fi
  fi

  if ! TRIGGERS_PATH="$TRIGGERS_DIR" STATE_AGENT_TYPE="$AGENT_TYPE" python3 - <<'PYEOF'
import datetime, json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_PATH"])
from _edamame_cli import cli_rpc

real_agent_type = os.environ["STATE_AGENT_TYPE"]
agent_type = "benchmark"
agent_instance_id = "e2e-divergence-stale-state-{}".format(real_agent_type)
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
stale_ingested = now - datetime.timedelta(minutes=30)

window = {
    "window_start": (now - datetime.timedelta(minutes=35)).isoformat().replace("+00:00", "Z"),
    "window_end": (now - datetime.timedelta(minutes=34)).isoformat().replace("+00:00", "Z"),
    "agent_type": agent_type,
    "agent_instance_id": agent_instance_id,
    "predictions": [
        {
            "agent_type": agent_type,
            "agent_instance_id": agent_instance_id,
            "session_key": "e2e_divergence_stale_state",
            "action": "Harness divergence stale state",
            "tools_called": ["run"],
            "scope_process_paths": ["*/divergence_probe"],
            "scope_parent_paths": [],
            "scope_grandparent_paths": [],
            "scope_any_lineage_paths": [],
            "expected_traffic": ["api.anthropic.com:443"],
            "expected_sensitive_files": [],
            "expected_lan_devices": [],
            "expected_local_open_ports": [],
            "expected_process_paths": ["*/divergence_probe"],
            "expected_parent_paths": [],
            "expected_grandparent_paths": [],
            "expected_open_files": [],
            "expected_l7_protocols": [],
            "expected_system_config": [],
            "not_expected_traffic": [],
            "not_expected_sensitive_files": [],
            "not_expected_lan_devices": [],
            "not_expected_local_open_ports": [],
            "not_expected_process_paths": [],
            "not_expected_parent_paths": [],
            "not_expected_grandparent_paths": [],
            "not_expected_open_files": [],
            "not_expected_l7_protocols": [],
            "not_expected_system_config": [],
            "raw_input": None,
        }
    ],
    "contributors": [],
    "version": "e2e/divergence-stale-state",
    "hash": "",
    "ingested_at": stale_ingested.isoformat().replace("+00:00", "Z"),
}

cli_rpc("clear_behavioral_model")
cli_rpc("clear_divergence_state")
cli_rpc("clear_divergence_history")
cli_rpc("start_divergence_engine", "[true, 300]")
cli_rpc("upsert_behavioral_model", json.dumps({"window_json": json.dumps(window)}))
cli_rpc("debug_run_divergence_tick")
PYEOF
  then
    warn "  Failed to seed stale divergence state model"
    rc=1
    if [[ "$STRICT" -eq 1 ]]; then
      return 1
    fi
  else
    if ! assert_divergence_verdict_state "Stale state" "STALE" 1 1200; then
      rc=1
      if [[ "$STRICT" -eq 1 ]]; then
        return 1
      fi
    fi
  fi

  if ! prepare_scenario_baseline "divergence" "divergence_verdict"; then
    warn "  Failed to prepare divergence state roundtrip baseline"
    rc=1
    if [[ "$STRICT" -eq 1 ]]; then
      return 1
    fi
  else
    INJECTOR_PID=""
    run_injector "divergence" "$DIVERGENCE_DURATION"
    wait_for_detection_readiness "divergence" "divergence_verdict" 60 || true
    python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_divergence_tick >/dev/null 2>&1 || true

    local roundtrip_status
    roundtrip_status="$(TRIGGERS_PATH="$TRIGGERS_DIR" python3 - <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.environ["TRIGGERS_PATH"])
from _edamame_cli import cli_rpc

summary = cli_rpc("get_divergence_verdict")
history = cli_rpc("get_divergence_history", "[5]")
history = history if isinstance(history, list) else []

verdict = str(summary.get("verdict") or "").strip().upper()
entry_id = str(summary.get("entry_id") or "").strip()
trace_available = bool(summary.get("trace_available"))
evidence = summary.get("evidence") or []
finding_key = ""
for item in evidence:
    if not isinstance(item, dict):
        continue
    finding_key = str(item.get("finding_key") or "").strip()
    if finding_key:
        break

trace_ok = True
trace_state = "not_requested"
if trace_available and entry_id:
    trace = cli_rpc("get_divergence_debug_trace", json.dumps([entry_id]))
    trace_ok = isinstance(trace, dict) and isinstance(trace.get("telemetry_snapshot"), dict)
    trace_state = "present" if trace_ok else "invalid"
elif entry_id:
    trace = cli_rpc("get_divergence_debug_trace", json.dumps([entry_id]))
    trace_ok = isinstance(trace, dict) and trace.get("trace") is None
    trace_state = "retention_disabled" if trace_ok else "unexpected"

dismiss_ok = False
undismiss_ok = False
history_ok = False

if verdict == "DIVERGENCE" and entry_id and finding_key:
    dismiss = cli_rpc("dismiss_divergence_evidence", json.dumps([finding_key]))
    after_dismiss = cli_rpc("get_divergence_verdict")
    after_dismiss_evidence = after_dismiss.get("evidence") or []
    dismiss_ok = bool(dismiss.get("success")) and any(
        isinstance(item, dict)
        and str(item.get("finding_key") or "").strip() == finding_key
        and bool(item.get("dismissed"))
        for item in after_dismiss_evidence
    )

    undismiss = cli_rpc("undismiss_divergence_evidence", json.dumps([finding_key]))
    after_undismiss = cli_rpc("get_divergence_verdict")
    after_undismiss_evidence = after_undismiss.get("evidence") or []
    undismiss_ok = bool(undismiss.get("success")) and any(
        isinstance(item, dict)
        and str(item.get("finding_key") or "").strip() == finding_key
        and not bool(item.get("dismissed"))
        for item in after_undismiss_evidence
    )

    history_ids = set()
    for h in history:
        if isinstance(h, dict):
            hid = str(h.get("entry_id") or "").strip()
            if hid:
                history_ids.add(hid)
    history_ok = bool(entry_id) and entry_id in history_ids

ok = all(
    [
        verdict == "DIVERGENCE",
        bool(entry_id),
        bool(finding_key),
        dismiss_ok,
        undismiss_ok,
        trace_ok,
        history_ok,
    ]
)
message = (
    "verdict={} entry_id={} finding_key={} dismiss_ok={} "
    "undismiss_ok={} trace_state={} history_ok={}"
).format(
    verdict or "NONE", entry_id or "missing", finding_key or "missing",
    int(dismiss_ok), int(undismiss_ok), trace_state, int(history_ok),
)
print(("OK" if ok else "FAIL") + "|" + message)
PYEOF
)"

    stop_injector
    run_injector_cleanup

    local roundtrip_state="${roundtrip_status%%|*}"
    local roundtrip_message="${roundtrip_status#*|}"
    if [[ "$roundtrip_state" == "OK" ]]; then
      log "  Dismissal/debug-trace roundtrip: $roundtrip_message"
    else
      warn "  Dismissal/debug-trace roundtrip failed: $roundtrip_message"
      rc=1
      if [[ "$STRICT" -eq 1 ]]; then
        return 1
      fi
    fi
  fi

  return "$rc"
}

merge_snapshot_json() {
  local label="$1"
  local cli_bin
  if ! cli_bin="$(find_edamame_cli_bin)"; then
    echo "{\"error\":\"edamame_cli_not_found\",\"label\":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$label")}"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo '{"dry_run":true}'
    return 0
  fi
  local raw_file
  raw_file="$(mktemp "${TMPDIR:-/tmp}/edamame-merge-raw.XXXXXX")"
  "$cli_bin" rpc get_behavioral_model --pretty >"$raw_file" 2>/dev/null || true
  set +e
  MERGE_LABEL="$label" MERGE_RAW_FILE="$raw_file" python3 <<'PY'
import json, os, re, sys
from pathlib import Path

def behavioral_from_cli_output(text):
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")
    if text.startswith("Result: "):
        payload = text.split("Result: ", 1)[1].strip()
        first = json.loads(payload)
    else:
        first = json.loads(text)
    if isinstance(first, str):
        return json.loads(first)
    return first

label = os.environ.get("MERGE_LABEL", "")
raw_path = os.environ.get("MERGE_RAW_FILE", "")
_dt = __import__("datetime")
_now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
out = {
    "kind": "merge_snapshot",
    "label": label,
    "timestamp_utc": _now,
}
try:
    raw = Path(raw_path).read_text(encoding="utf-8") if raw_path else ""
except OSError as exc:
    out["read_error"] = str(exc)
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)
try:
    m = behavioral_from_cli_output(raw)
except Exception as exc:
    out["parse_error"] = str(exc)
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)

if m == {"model": None} or (len(m) == 1 and m.get("model") is None):
    out["model_null"] = True
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)

contribs = m.get("contributors") if isinstance(m.get("contributors"), list) else []
out["contributor_count"] = len(contribs)
out["contributors"] = []
for c in contribs:
    if not isinstance(c, dict):
        continue
    out["contributors"].append({
        "agent_type": c.get("agent_type"),
        "agent_instance_id": c.get("agent_instance_id"),
        "hash": (c.get("hash") or "")[:32] + ("..." if len(str(c.get("hash") or "")) > 32 else ""),
    })

preds = m.get("predictions") if isinstance(m.get("predictions"), list) else []
out["predictions_total"] = len(preds)
by_agent = {}
sk_by_agent = {}
for p in preds:
    if not isinstance(p, dict):
        continue
    at = p.get("agent_type") or "unknown"
    aid = p.get("agent_instance_id") or ""
    key = f"{at}:{aid}"
    by_agent[key] = by_agent.get(key, 0) + 1
    sk_by_agent.setdefault(key, [])
    sk = p.get("session_key")
    if sk and sk not in sk_by_agent[key]:
        sk_by_agent[key].append(sk)
out["predictions_by_agent_instance"] = by_agent
out["session_key_samples"] = {k: v[:8] for k, v in sk_by_agent.items()}

out["merge_observation"] = (
    "multiple_contributors" if len(contribs) > 1
    else "single_or_flat_contributor"
)
if len(contribs) > 1:
    out["merge_capability_note"] = (
        "Core returned a merged behavioral model with multiple contributor entries; "
        "predictions aggregate slices from each producer key."
    )
else:
    out["merge_capability_note"] = (
        "Only one contributor row in this snapshot (normal if only one agent_type has pushed recently, "
        "or if the store flattens a single producer)."
    )

print(json.dumps(out, ensure_ascii=False))
PY
  local py_exit=$?
  set -e
  rm -f "$raw_file"
  return "$py_exit"
}

write_intent_leg_stats() {
  local key="$1" rc="$2" sec="$3"
  local r="$ROUND_INDEX"
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  python3 -c "import json,sys; print(json.dumps({'exit':int(sys.argv[1]),'seconds':int(sys.argv[2]),'log':sys.argv[3],'diag':sys.argv[4]}))" \
    "$rc" "$sec" "round_${r}_${key}.log" "round_${r}_${key}_diag.json" >"$REPORT_DIR/round_${r}_${key}.stats.json"
}

run_intent_leg() {
  local key="$1" script="$2" timeout_secs="$3" human="$4"
  [[ -f "$script" ]] || die "Missing $script"
  local log="$REPORT_DIR/round_${ROUND_INDEX}_${key}.log"
  local diag="$REPORT_DIR/round_${ROUND_INDEX}_${key}_diag.json"
  export E2E_DIAGNOSTICS_FILE="$diag"
  local t0 t1 elapsed rc=0
  t0="$(date +%s)"
  log "Intent E2E: $human"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run_timeout "$timeout_secs" bash "$script"
    return 0
  fi
  set -o pipefail
  run_timeout "$timeout_secs" bash "$script" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set +o pipefail
  t1="$(date +%s)"
  elapsed=$((t1 - t0))
  write_intent_leg_stats "$key" "$rc" "$elapsed"
  return "$rc"
}

intent_parallel_worker() {
  local key="$1" script="$2" timeout_secs="$3"
  export E2E_POLL_ATTEMPTS="$INTENT_POLL_ATTEMPTS"
  export E2E_DIAGNOSTICS_FILE="$REPORT_DIR/round_${ROUND_INDEX}_${key}_diag.json"
  local t0 t1 elapsed rc=0
  local log="$REPORT_DIR/round_${ROUND_INDEX}_${key}.log"
  t0="$(date +%s)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run_timeout "$timeout_secs" bash "$script"
    rc=$?
  else
    run_timeout "$timeout_secs" bash "$script" >"$log" 2>&1
    rc=$?
  fi
  t1="$(date +%s)"
  elapsed=$((t1 - t0))
  write_intent_leg_stats "$key" "$rc" "$elapsed"
  exit "$rc"
}

run_intent_suite() {
  export E2E_POLL_ATTEMPTS="$INTENT_POLL_ATTEMPTS"
  if [[ -z "${E2E_OPENCLAW_AGENT_INSTANCE_ID:-}" ]]; then
    export E2E_OPENCLAW_AGENT_INSTANCE_ID="e2e-harness-${RUN_TS}"
  fi
  log "OpenClaw E2E agent_instance_id=${E2E_OPENCLAW_AGENT_INSTANCE_ID}"
  local rc=0
  local -a keys=()
  local -a humans=()
  local -a scripts=()
  local -a timeouts=()
  local -a pids=()

  while IFS=$'\t' read -r key human script timeout_secs; do
    [[ -n "$key" ]] || continue
    keys+=("$key")
    humans+=("$human")
    scripts+=("$script")
    timeouts+=("$timeout_secs")
  done < <(emit_intent_agent_lines)

  ((${#keys[@]} > 0)) || die "No intent-capable agents found in supported-agent registry."

  if [[ "$DRY_RUN" -eq 0 ]]; then
    local key
    for key in "${keys[@]}"; do
      rm -f \
        "$REPORT_DIR/round_${ROUND_INDEX}_${key}.stats.json" \
        "$REPORT_DIR/round_${ROUND_INDEX}_${key}_diag.json" \
        "$REPORT_DIR/round_${ROUND_INDEX}_${key}.log" 2>/dev/null || true
    done
  fi

  if [[ "$PARALLEL_INTENT" -eq 1 ]]; then
    log "Intent E2E: parallel ($(printf '%s, ' "${humans[@]}" | sed 's/, $//'))"
    local i
    for i in "${!keys[@]}"; do
      intent_parallel_worker "${keys[$i]}" "${scripts[$i]}" "${timeouts[$i]}" &
      pids+=("$!")
    done
    local pid
    for pid in "${pids[@]}"; do
      if ! wait "$pid"; then rc=1; fi
    done
    return "$rc"
  fi

  local i
  for i in "${!keys[@]}"; do
    run_intent_leg "${keys[$i]}" "${scripts[$i]}" "${timeouts[$i]}" "${humans[$i]}" || rc=1
  done
  return "$rc"
}

DETECTION_VERIFY_RETRIES=5
DETECTION_VERIFY_INTERVAL=30

scenario_expected_check() {
  case "$1" in
    blacklist_comm)          echo "blacklisted_sessions" ;;
    cve_token_exfil)         echo "token_exfiltration" ;;
    cve_sandbox_escape)      echo "sandbox_exploitation" ;;
    divergence)              echo "divergence_verdict" ;;
    memory_poisoning)        echo "token_exfiltration" ;;
    goal_drift)              echo "divergence_verdict" ;;
    credential_sprawl)       echo "token_exfiltration" ;;
    tool_poisoning_effects)  echo "token_exfiltration" ;;
    supply_chain_exfil)      echo "credential_harvest" ;;
    npm_rat_beacon)          echo "token_exfiltration" ;;
    file_events)             echo "file_system_tampering" ;;
    *)                       echo "" ;;
  esac
}

count_vulnerability_findings_for_check() {
  local check="$1"
  vulnerability_finding_status_for_check "$check" | cut -d'|' -f1
}

count_vulnerability_findings_for_scenario() {
  local scenario="$1"
  local check="$2"
  vulnerability_finding_status_for_scenario "$scenario" "$check" | cut -d'|' -f1
}

vulnerability_finding_status_for_check() {
  local check="$1"
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
check = '$check'
current = 0
history_count = 0
try:
    report = cli_rpc('get_vulnerability_findings')
    findings = report.get('findings', []) if isinstance(report, dict) else []
    current = len([f for f in findings if f.get('check') == check])
except Exception:
    pass
try:
    history = cli_rpc('get_vulnerability_history', '{\"limit\": 20}')
    if isinstance(history, list):
        for entry in history:
            for f in (entry.get('findings') or []):
                if f.get('check') == check:
                    history_count += 1
except Exception:
    pass
print(f'{current + history_count}|{current}|{history_count}')
" 2>/dev/null || echo "0|0|0"
}

vulnerability_finding_status_for_scenario() {
  local scenario="$1"
  local check="$2"
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc

scenario = '$scenario'.strip()
check = '$check'

SCENARIO_MARKERS = {
    'cve_token_exfil': ['_exfil_token', '_exfil'],
    'memory_poisoning': ['_memory_poison', 'memory_poisoned.md'],
    'credential_sprawl': ['_sprawl_key', '_sprawl', 'demo_openclaw_sprawl'],
    'tool_poisoning_effects': ['_tool_poison', 'demo_openclaw_tool_poison'],
    'file_events': ['_fim_test', '_fim_suspicious'],
}

SCENARIO_PORTS = {
    'cve_token_exfil': [63169],
    'credential_sprawl': [63171],
    'tool_poisoning_effects': [63172],
}

markers = [marker.lower() for marker in SCENARIO_MARKERS.get(scenario, [])]
ports = set(SCENARIO_PORTS.get(scenario, []))

def matches(finding):
    if not isinstance(finding, dict):
        return False
    if finding.get('check') != check:
        return False
    if not markers and not ports:
        return True

    joined = '\\n'.join(str(path) for path in (finding.get('open_files') or [])).lower()
    if markers and any(marker in joined for marker in markers):
        return True

    port = finding.get('destination_port')
    try:
        port = int(port) if port is not None else None
    except Exception:
        port = None
    return port in ports

current = 0
history_count = 0
try:
    report = cli_rpc('get_vulnerability_findings')
    findings = report.get('findings', []) if isinstance(report, dict) else []
    current = sum(1 for finding in findings if matches(finding))
except Exception:
    pass
try:
    history = cli_rpc('get_vulnerability_history', '{\"limit\": 20}')
    if isinstance(history, list):
        for entry in history:
            for finding in (entry.get('findings') or []):
                if matches(finding):
                    history_count += 1
except Exception:
    pass
print(f'{current + history_count}|{current}|{history_count}')
" 2>/dev/null || echo "0|0|0"
}

token_family_l7_status() {
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
sessions = cli_rpc('get_anomalous_sessions')
active = [s for s in sessions if isinstance(s, dict) and (s.get('status') or {}).get('active')]
active_with_of = [s for s in active if len((s.get('l7') or {}).get('open_files', [])) > 0]
print(f'{len(active)}|{len(active_with_of)}')
" 2>/dev/null || echo "0|0"
}

sandbox_exploitation_readiness_status() {
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
sessions = cli_rpc('get_current_sessions')
active = 0
candidates = 0
for session in sessions or []:
    if not isinstance(session, dict):
        continue
    if not (session.get('status') or {}).get('active'):
        continue
    active += 1
    l7 = session.get('l7') or {}
    paths = [
        str(l7.get('parent_process_path') or ''),
        str(l7.get('parent_script_path') or ''),
        str(l7.get('process_path') or ''),
    ]
    spawned_from_tmp = bool(l7.get('spawned_from_tmp'))
    suspicious = spawned_from_tmp or any('/tmp/' in path for path in paths if path)
    if suspicious:
        candidates += 1
print(f'{active}|{candidates}')
" 2>/dev/null || echo "0|0"
}

credential_harvest_l7_status() {
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc

LABEL_MARKERS = {
    'ssh': ['/.ssh/', '_supply_chain_key', '_sc_ssh'],
    'aws': ['/.aws/', '_sc_credentials'],
    'gcp': ['/gcloud/', '_sc_adc.json'],
    'git': ['git-credentials', '/.git-credentials'],
    'kube': ['/.kube/', '_sc_config'],
    'docker': ['/.docker/', '_sc_config.json'],
    'vault': ['vault-token'],
    'env': ['/.env_', '_supply_chain'],
    'crypto': ['/.bitcoin/', '/.ethereum/', '/solana/'],
}

def classify(paths):
    labels = set()
    for raw in paths or []:
        p = str(raw).lower()
        for label, needles in LABEL_MARKERS.items():
            if any(needle in p for needle in needles):
                labels.add(label)
    return labels

sessions = cli_rpc('get_current_sessions')
active = [s for s in sessions if isinstance(s, dict) and (s.get('status') or {}).get('active')]
candidates = 0
max_labels = 0
for session in active:
    l7 = session.get('l7') or {}
    labels = classify(l7.get('open_files') or [])
    max_labels = max(max_labels, len(labels))
    if len(labels) >= 3:
        candidates += 1
print(f'{len(active)}|{candidates}|{max_labels}')
" 2>/dev/null || echo "0|0|0"
}

fim_event_status() {
  python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
snapshot = cli_rpc('get_file_events')
total = snapshot.get('event_count', 0) if isinstance(snapshot, dict) else 0
sensitive = len(snapshot.get('sensitive_events', [])) if isinstance(snapshot, dict) else 0
print(f'{total}|{sensitive}')
" 2>/dev/null || echo "0|0"
}

prepare_scenario_baseline() {
  local scenario="$1"
  local expected="$2"

  VERIFY_BASELINE_VULN_TOTAL=0

  case "$expected" in
    token_exfiltration|sandbox_exploitation|credential_harvest|file_system_tampering)
      if [[ "$DRY_RUN" -eq 1 ]]; then
        log "  [DRY-RUN] reset vulnerability detector state for $scenario ($expected)"
        return 0
      fi

      if [[ "$expected" == "file_system_tampering" ]]; then
        python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_file_events >/dev/null 2>&1 || true
        python3 "$TRIGGERS_DIR/_edamame_cli.py" start_file_monitor '[[]]' >/dev/null 2>&1 || true
        log "  Started FIM for file_system_tampering scenario"
      fi
      python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_vulnerability_history >/dev/null 2>&1 || true

      local waited=0
      local max_wait=45
      while ((waited <= max_wait)); do
        python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
        sleep 2

        local status total current history
        status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        total="${status%%|*}"
        local rest="${status#*|}"
        current="${rest%%|*}"
        history="${rest#*|}"

        if [[ "$current" -eq 0 && "$history" -eq 0 ]]; then
          log "  Reset vulnerability detector state for $expected"
          VERIFY_BASELINE_VULN_TOTAL=0
          return 0
        fi

        log "  Waiting for stale $expected findings to clear: current=$current history=$history"
        run_cmd sleep 5
        waited=$((waited + 5))
      done

      VERIFY_BASELINE_VULN_TOTAL="$(count_vulnerability_findings_for_scenario "$scenario" "$expected")"
      warn "Stale $expected findings remain after reset; using baseline=$VERIFY_BASELINE_VULN_TOTAL"
      ;;
    divergence_verdict)
      if [[ "$DRY_RUN" -eq 1 ]]; then
        log "  [DRY-RUN] reseed divergence model for $scenario"
        return 0
      fi

      python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_divergence_state >/dev/null 2>&1 || true
      python3 "$TRIGGERS_DIR/_edamame_cli.py" clear_divergence_history >/dev/null 2>&1 || true
      ensure_divergence_harness_ready || return 1
      wait_for_divergence_model_ready || return 1
      log "  Reseeded divergence model for $scenario"
      ;;
  esac
}

wait_for_detection_readiness() {
  local scenario="$1"
  local expected="$2"
  local max_wait="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  [DRY-RUN] wait_for_detection_readiness $scenario -> $expected (${max_wait}s)"
    return 0
  fi

  case "$expected" in
    token_exfiltration)
      local waited=0
      local interval=10
      while ((waited < max_wait)); do
        local found_status found found_current found_history
        local l7_status anomalous_active anomalous_with_of

        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  Detection landed during warm-up: $((found - VERIFY_BASELINE_VULN_TOTAL)) new $expected finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          return 0
        fi

        l7_status="$(token_family_l7_status)"
        anomalous_active="${l7_status%%|*}"
        anomalous_with_of="${l7_status#*|}"
        if [[ "$anomalous_active" -gt 0 && "$anomalous_with_of" -gt 0 ]]; then
          log "  L7 readiness reached for $scenario: active_anomalous=$anomalous_active with_open_files=$anomalous_with_of"
          return 0
        fi

        local remaining=$((max_wait - waited))
        local sleep_for="$interval"
        if ((remaining < interval)); then
          sleep_for="$remaining"
        fi
        if ((sleep_for <= 0)); then
          break
        fi
        log "  Waiting for L7 readiness: active_anomalous=$anomalous_active with_open_files=$anomalous_with_of (${waited}/${max_wait}s)"
        run_cmd sleep "$sleep_for"
        waited=$((waited + sleep_for))
      done
      log "  L7 readiness timeout for $scenario after ${max_wait}s; proceeding to verification"
      ;;

    sandbox_exploitation)
      local waited=0
      local interval=10
      while ((waited < max_wait)); do
        local found_status found found_current found_history
        local readiness_status active_sessions sandbox_candidates

        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  Detection landed during warm-up: $((found - VERIFY_BASELINE_VULN_TOTAL)) new sandbox_exploitation finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          return 0
        fi

        readiness_status="$(sandbox_exploitation_readiness_status)"
        active_sessions="${readiness_status%%|*}"
        sandbox_candidates="${readiness_status#*|}"
        if [[ "$sandbox_candidates" -gt 0 ]]; then
          log "  Sandbox readiness reached for $scenario: active_sessions=$active_sessions suspicious_lineage=$sandbox_candidates"
          return 0
        fi

        local remaining=$((max_wait - waited))
        local sleep_for="$interval"
        if ((remaining < interval)); then
          sleep_for="$remaining"
        fi
        if ((sleep_for <= 0)); then
          break
        fi
        log "  Waiting for sandbox readiness: active_sessions=$active_sessions suspicious_lineage=$sandbox_candidates (${waited}/${max_wait}s)"
        run_cmd sleep "$sleep_for"
        waited=$((waited + sleep_for))
      done
      log "  Sandbox readiness timeout for $scenario after ${max_wait}s; proceeding to verification"
      ;;

    credential_harvest)
      local waited=0
      local interval=10
      while ((waited < max_wait)); do
        local found_status found found_current found_history
        local harvest_status active_sessions harvest_candidates harvest_max_labels

        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  Detection landed during warm-up: $((found - VERIFY_BASELINE_VULN_TOTAL)) new credential_harvest finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          return 0
        fi

        harvest_status="$(credential_harvest_l7_status)"
        active_sessions="${harvest_status%%|*}"
        local harvest_rest="${harvest_status#*|}"
        harvest_candidates="${harvest_rest%%|*}"
        harvest_max_labels="${harvest_rest#*|}"
        if [[ "$harvest_candidates" -gt 0 ]]; then
          log "  Harvest readiness reached for $scenario: active_sessions=$active_sessions candidates=$harvest_candidates max_labels=$harvest_max_labels"
          return 0
        fi

        local remaining=$((max_wait - waited))
        local sleep_for="$interval"
        if ((remaining < interval)); then
          sleep_for="$remaining"
        fi
        if ((sleep_for <= 0)); then
          break
        fi
        log "  Waiting for harvest readiness: active_sessions=$active_sessions candidates=$harvest_candidates max_labels=$harvest_max_labels (${waited}/${max_wait}s)"
        run_cmd sleep "$sleep_for"
        waited=$((waited + sleep_for))
      done
      log "  Harvest readiness timeout for $scenario after ${max_wait}s; proceeding to verification"
      ;;

    file_system_tampering)
      local waited=0
      local interval=5
      while ((waited < max_wait)); do
        local found_status found found_current found_history
        local fim_status fim_total fim_sensitive

        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  Detection landed during warm-up: $((found - VERIFY_BASELINE_VULN_TOTAL)) new file_system_tampering finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          return 0
        fi

        fim_status="$(fim_event_status)"
        fim_total="${fim_status%%|*}"
        fim_sensitive="${fim_status#*|}"
        if [[ "$fim_sensitive" -gt 0 ]]; then
          log "  FIM readiness reached for $scenario: total_events=$fim_total sensitive=$fim_sensitive"
          return 0
        fi

        local remaining=$((max_wait - waited))
        local sleep_for="$interval"
        if ((remaining < interval)); then
          sleep_for="$remaining"
        fi
        if ((sleep_for <= 0)); then
          break
        fi
        log "  Waiting for FIM readiness: total_events=$fim_total sensitive=$fim_sensitive (${waited}/${max_wait}s)"
        run_cmd sleep "$sleep_for"
        waited=$((waited + sleep_for))
      done
      log "  FIM readiness timeout for $scenario after ${max_wait}s; proceeding to verification"
      ;;

    *)
      if [[ "$max_wait" -gt 0 ]]; then
        log "  waiting ${max_wait}s for L7 attribution..."
        run_cmd sleep "$max_wait"
      fi
      ;;
  esac
}

verify_detection() {
  local scenario="$1"
  local expected
  expected="$(scenario_expected_check "$scenario")"
  if [[ -z "$expected" ]]; then
    warn "No expected detection defined for $scenario; skipping verification"
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "  [DRY-RUN] verify_detection $scenario -> $expected"
    return 0
  fi

  if [[ "$expected" == "divergence_verdict" ]]; then
    wait_for_divergence_model_ready || return 1
  fi

  if [[ "$expected" == "divergence_verdict" ]]; then
    log "  Forcing divergence engine tick..."
    python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_divergence_tick >/dev/null 2>&1 || true
  else
    log "  Forcing vulnerability detector tick..."
    python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
  fi
  sleep 3

  local attempt=0
  while ((attempt < DETECTION_VERIFY_RETRIES)); do
    attempt=$((attempt + 1))
    log "  Verify $scenario (attempt $attempt/$DETECTION_VERIFY_RETRIES): expecting $expected"

    local detected=0

    case "$expected" in
      blacklisted_sessions)
        local bl_count
        bl_count="$(python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
sessions = cli_rpc('get_blacklisted_sessions')
target_ips = {'5.188.11.1', '45.95.232.1', '2.57.122.1'}
active = [s for s in sessions if isinstance(s, dict)
    and s.get('session',{}).get('dst_ip') in target_ips
    and (s.get('status') or {}).get('active')]
print(len(active))
" 2>/dev/null || echo "0")"
        if [[ "$bl_count" -gt 0 ]]; then
          log "  DETECTED: $bl_count active blacklisted session(s) to FireHOL IPs"
          detected=1
        fi

        # Supplementary: verify that the vulnerability detector also raised a
        # skill_supply_chain finding for blacklisted communication.
        local sc_count
        sc_count="$(python3 -c "
import sys; sys.path.insert(0, '$TRIGGERS_DIR')
from _edamame_cli import cli_rpc
report = cli_rpc('get_vulnerability_findings')
findings = report.get('findings', []) if isinstance(report, dict) else []
sc = [f for f in findings if f.get('check') == 'skill_supply_chain']
print(len(sc))
" 2>/dev/null || echo "0")"
        if [[ "$sc_count" -gt 0 ]]; then
          log "  DETECTED: $sc_count skill_supply_chain vulnerability finding(s) for blacklisted traffic"
        else
          log "  NOTE: no skill_supply_chain vulnerability findings yet (blacklisted sessions detected=$bl_count)"
        fi
        ;;

      divergence_verdict)
        local verdict_status divergence_state divergence_message
        verdict_status="$(divergence_semantic_status_for_scenario "$scenario" 2>/dev/null || echo "WAIT|semantic probe failed")"
        divergence_state="${verdict_status%%|*}"
        divergence_message="${verdict_status#*|}"
        if [[ "$divergence_state" == "OK" ]]; then
          log "  DETECTED: $divergence_message"
          detected=1
        else
          log "  Divergence status: $divergence_message"
        fi
        ;;

      token_exfiltration)
        local found found_current found_history l7_status
        local found_status
        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        l7_status="$(token_family_l7_status)"
        local anomalous_active="${l7_status%%|*}"
        local anomalous_with_of="${l7_status#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new $expected finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          detected=1
        elif [[ "$expected" == "token_exfiltration" && "$anomalous_active" -gt 0 && "$anomalous_with_of" -gt 0 ]]; then
          log "  L7 overlap present; forcing immediate vulnerability detector tick..."
          python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
          sleep 3
          found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
          found="${found_status%%|*}"
          found_rest="${found_status#*|}"
          found_current="${found_rest%%|*}"
          found_history="${found_rest#*|}"
          if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
            log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new $expected finding(s) after immediate detector tick (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
            detected=1
          else
            log "  L7 status: active_anomalous=$anomalous_active with_open_files=$anomalous_with_of (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL after immediate tick)"
          fi
        else
          log "  L7 status: active_anomalous=$anomalous_active with_open_files=$anomalous_with_of (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL)"
        fi
        ;;

      sandbox_exploitation)
        local found found_current found_history readiness_status
        local found_status
        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        readiness_status="$(sandbox_exploitation_readiness_status)"
        local active_sessions="${readiness_status%%|*}"
        local sandbox_candidates="${readiness_status#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new sandbox_exploitation finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          detected=1
        elif [[ "$sandbox_candidates" -gt 0 ]]; then
          log "  Sandbox lineage present; forcing immediate vulnerability detector tick..."
          python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
          sleep 3
          found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
          found="${found_status%%|*}"
          found_rest="${found_status#*|}"
          found_current="${found_rest%%|*}"
          found_history="${found_rest#*|}"
          if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
            log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new sandbox_exploitation finding(s) after immediate detector tick (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
            detected=1
          else
            log "  Sandbox status: active_sessions=$active_sessions suspicious_lineage=$sandbox_candidates (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL after immediate tick)"
          fi
        else
          log "  Sandbox status: active_sessions=$active_sessions suspicious_lineage=$sandbox_candidates (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL)"
        fi
        ;;

      credential_harvest)
        local found found_current found_history harvest_status
        local found_status
        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        harvest_status="$(credential_harvest_l7_status)"
        local active_sessions="${harvest_status%%|*}"
        local harvest_rest="${harvest_status#*|}"
        local harvest_candidates="${harvest_rest%%|*}"
        local harvest_max_labels="${harvest_rest#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new credential_harvest finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          detected=1
        elif [[ "$harvest_candidates" -gt 0 ]]; then
          log "  Harvest candidates present; forcing immediate vulnerability detector tick..."
          python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
          sleep 3
          found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
          found="${found_status%%|*}"
          found_rest="${found_status#*|}"
          found_current="${found_rest%%|*}"
          found_history="${found_rest#*|}"
          if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
            log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new credential_harvest finding(s) after immediate detector tick (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
            detected=1
          else
            log "  Harvest status: active_sessions=$active_sessions candidates=$harvest_candidates max_labels=$harvest_max_labels (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL after immediate tick)"
          fi
        else
          log "  Harvest status: active_sessions=$active_sessions candidates=$harvest_candidates max_labels=$harvest_max_labels (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL)"
        fi
        ;;

      file_system_tampering)
        local found found_current found_history fim_status
        local found_status
        found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
        found="${found_status%%|*}"
        local found_rest="${found_status#*|}"
        found_current="${found_rest%%|*}"
        found_history="${found_rest#*|}"
        fim_status="$(fim_event_status)"
        local fim_total="${fim_status%%|*}"
        local fim_sensitive="${fim_status#*|}"
        if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
          log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new file_system_tampering finding(s) (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
          detected=1
        elif [[ "$fim_sensitive" -gt 0 ]]; then
          log "  FIM sensitive events present; forcing immediate vulnerability detector tick..."
          python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
          sleep 3
          found_status="$(vulnerability_finding_status_for_scenario "$scenario" "$expected")"
          found="${found_status%%|*}"
          found_rest="${found_status#*|}"
          found_current="${found_rest%%|*}"
          found_history="${found_rest#*|}"
          if [[ "$found" -gt "$VERIFY_BASELINE_VULN_TOTAL" ]]; then
            log "  DETECTED: $((found - VERIFY_BASELINE_VULN_TOTAL)) new file_system_tampering finding(s) after immediate detector tick (current=$found_current history=$found_history baseline=$VERIFY_BASELINE_VULN_TOTAL)"
            detected=1
          else
            log "  FIM status: total_events=$fim_total sensitive=$fim_sensitive (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL after immediate tick)"
          fi
        else
          log "  FIM status: total_events=$fim_total sensitive=$fim_sensitive (total=$found baseline=$VERIFY_BASELINE_VULN_TOTAL)"
        fi
        ;;
    esac

    if [[ "$detected" -eq 1 ]]; then
      return 0
    fi

    if ((attempt < DETECTION_VERIFY_RETRIES)); then
      log "  Not yet detected; retrying in ${DETECTION_VERIFY_INTERVAL}s (L7 attribution may need more cycles)..."
      if [[ "$expected" == "divergence_verdict" ]]; then
        python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_divergence_tick >/dev/null 2>&1 || true
      else
        python3 "$TRIGGERS_DIR/_edamame_cli.py" debug_run_vulnerability_detector_tick >/dev/null 2>&1 || true
      fi
      sleep "$DETECTION_VERIFY_INTERVAL"
    fi
  done

  log "  FAIL: $scenario did NOT produce expected detection '$expected' after $DETECTION_VERIFY_RETRIES attempts"
  return 1
}

run_cve_suite() {
  local scenario duration rc=0
  local scenarios=(blacklist_comm cve_token_exfil cve_sandbox_escape divergence memory_poisoning goal_drift credential_sprawl tool_poisoning_effects supply_chain_exfil npm_rat_beacon file_events)
  ensure_capture_running
  run_injector_cleanup
  for scenario in "${scenarios[@]}"; do
    local expected
    expected="$(scenario_expected_check "$scenario")"
    case "$scenario" in
      divergence|goal_drift) duration="$DIVERGENCE_DURATION" ;;
      *) duration="$SCENARIO_DURATION" ;;
    esac

    local l7_wait
    case "$scenario" in
      divergence|goal_drift) l7_wait=60 ;;
      blacklist_comm) l7_wait=30 ;;
      file_events) l7_wait=15 ;;
      *) l7_wait=120 ;;
    esac

    if [[ "$expected" == "token_exfiltration" || "$expected" == "sandbox_exploitation" || "$expected" == "credential_harvest" || "$expected" == "file_system_tampering" || "$expected" == "divergence_verdict" ]]; then
      local min_duration
      min_duration=$((l7_wait + (DETECTION_VERIFY_RETRIES * DETECTION_VERIFY_INTERVAL) + 30))
      if ((duration < min_duration)); then
        duration="$min_duration"
      fi
    fi

    if ! prepare_scenario_baseline "$scenario" "$expected"; then
      warn "Scenario preflight failed for $scenario"
      rc=1
      if [[ "$STRICT" -eq 1 ]]; then
        return 1
      fi
      continue
    fi

    # Start trigger in background (stays alive for duration)
    INJECTOR_PID=""
    run_injector "$scenario" "$duration"

    # Wait for L7 attribution before verifying, but stop early once the relevant
    # signal shows up so short-lived sessions do not go inactive first.
    wait_for_detection_readiness "$scenario" "$expected" "$l7_wait"

    # Verify while trigger is still alive (sessions are active)
    if ! verify_detection "$scenario"; then
      rc=1
      if [[ "$STRICT" -eq 1 ]]; then
        stop_injector
        run_injector_cleanup
        return 1
      fi
    fi

    stop_injector
    run_injector_cleanup

    if [[ "$expected" == "file_system_tampering" ]]; then
      python3 "$TRIGGERS_DIR/_edamame_cli.py" stop_file_monitor >/dev/null 2>&1 || true
      log "  Stopped FIM after file_system_tampering scenario"
    fi

    if [[ "$CVE_COOLDOWN" -gt 0 ]]; then run_cmd sleep "$CVE_COOLDOWN"; fi
  done

  if ! run_divergence_engine_state_checks; then
    rc=1
  fi

  return "$rc"
}

finalize_summary() {
  if [[ "$DRY_RUN" -eq 1 ]]; then return 0; fi
  local end_epoch elapsed
  end_epoch="$(date +%s)"
  elapsed=$((end_epoch - HARNESS_START_EPOCH))
  MERGE_REPORT_JSONL="$REPORT_JSONL" MERGE_SUMMARY_MD="$SUMMARY_MD" MERGE_ELAPSED="$elapsed" \
    MERGE_FAILURE="$ANY_FAILURE" MERGE_FOCUS="$FOCUS" python3 <<'PY'
import json
import os
from pathlib import Path

report_path = Path(os.environ["MERGE_REPORT_JSONL"])
summary_path = Path(os.environ["MERGE_SUMMARY_MD"])
elapsed = int(os.environ.get("MERGE_ELAPSED", "0"))
failure = os.environ.get("MERGE_FAILURE", "0") == "1"
focus = os.environ.get("MERGE_FOCUS", "")

lines = []
if report_path.exists():
    lines = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines() if line.strip()]

round_rows = [x for x in lines if x.get("kind") == "round"]
merge_snaps = [x for x in lines if x.get("kind") == "merge_snapshot"]
rounds = len(round_rows)

with summary_path.open("w", encoding="utf-8") as f:
    f.write("# Agent security E2E harness report\n\n")
    f.write(f"- Focus: `{focus}`\n")
    f.write(f"- Wall time: {elapsed}s\n")
    f.write(f"- Rounds completed: {rounds}\n")
    f.write(f"- Overall: {'FAIL' if failure else 'PASS'}\n\n")
    if round_rows:
        intent_agents = json.loads(os.environ.get("INTENT_AGENTS_JSON", "[]"))
        intent_headers = [agent["agent_type"] for agent in intent_agents]
        f.write("## Rounds\n\n")
        headers = ["round", "phases", "intent", "cve", "first_fail"] + intent_headers
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for r in round_rows:
            legs = r.get("intent_legs") or {}

            def leg_cell(k):
                L = legs.get(k) or {}
                ex = L.get("exit")
                sec = L.get("seconds")
                if ex is None:
                    return "-"
                return f"{ex} / {sec}s"

            ff = r.get("intent_first_failure") or ""
            row = [
                str(r.get("round")),
                ",".join(r.get("phases") or []),
                str(r.get("intent_exit", "")),
                str(r.get("cve_exit", "")),
                ff,
            ] + [leg_cell(agent["agent_type"]) for agent in intent_agents]
            f.write("| " + " | ".join(row) + " |\n")
        f.write("\n")
        f.write("Per-round JSON in `report.jsonl` includes `intent_legs` with `diag_summary` when a leg failed and wrote `*_diag.json`.\n\n")
    f.write("## Merge analysis (last snapshot)\n\n")
    if merge_snaps:
        last = merge_snaps[-1]
        f.write(f"- Label: `{last.get('label')}`\n")
        f.write(f"- Contributors: {last.get('contributor_count')}\n")
        f.write(f"- Predictions total: {last.get('predictions_total')}\n")
        f.write(f"- Observation: {last.get('merge_observation')}\n")
        f.write(f"- Note: {last.get('merge_capability_note')}\n\n")
        if last.get("contributors"):
            f.write("| agent_type | agent_instance_id | hash (trimmed) |\n")
            f.write("|------------|-------------------|----------------|\n")
            for c in last["contributors"]:
                f.write(f"| {c.get('agent_type')} | {c.get('agent_instance_id')} | {c.get('hash')} |\n")
            f.write("\n")
        if last.get("predictions_by_agent_instance"):
            f.write("### Predictions by producer\n\n")
            for k, v in sorted(last["predictions_by_agent_instance"].items()):
                f.write(f"- `{k}`: {v}\n")
            f.write("\n")
    else:
        f.write("_No merge snapshots recorded._\n\n")
    f.write("## Raw events\n\n")
    f.write(f"- JSONL: `{report_path}`\n")
    f.write(f"- Console: `{report_path.parent / 'console.log'}`\n")
PY
}

validate_repos() {
  python3 "$SUPPORTED_AGENT_HELPER" validate || die "Supported-agent registry validation failed."
}

main() {
  local os_name
  os_name="$(uname -s)"
  case "$os_name" in
    Darwin)
      log "Platform: macOS"
      ;;
    Linux)
      log "Platform: Linux"
      # On Linux, packet capture requires CAP_NET_RAW or root.
      if [[ "$(id -u)" -ne 0 ]] && ! capsh --has-p=cap_net_raw 2>/dev/null; then
        warn "Running as non-root without CAP_NET_RAW; capture may fail."
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*)
      log "Platform: Windows (Git Bash)"
      # On Windows, packet capture requires Npcap and an elevated shell.
      # EDAMAME Security typically handles this when running as the app daemon,
      # but a bash session launched without Administrator rights may still see
      # permission errors when calling capture-related RPCs.
      warn "Packet capture on Windows requires Npcap and an elevated shell; start Git Bash / WSL as Administrator if capture RPCs fail."
      ;;
    *)
      die "Unsupported platform: $os_name (supported: macOS, Linux, Windows under Git Bash / WSL)."
      ;;
  esac
  require_command python3
  require_command curl
  [[ -f "$SUPPORTED_AGENT_HELPER" ]] || die "Missing supported-agent helper: $SUPPORTED_AGENT_HELPER"
  SUPPORTED_AGENT_TYPES_JSON="$(python3 "$SUPPORTED_AGENT_HELPER" types)" || die "Failed to load supported-agent types."
  INTENT_AGENTS_JSON="$(python3 "$SUPPORTED_AGENT_HELPER" list-intent)" || die "Failed to load intent agents."
  export INTENT_AGENTS_JSON
  validate_supported_agent_type "$AGENT_TYPE"
  validate_repos
  ensure_edamame_app
  trap restore_capture_state EXIT

  : >"$REPORT_JSONL"
  log "Report dir: $REPORT_DIR"
  log "Focus=$FOCUS duration=${DURATION_SECONDS}s interval=${ROUND_INTERVAL_SECONDS}s parallel_intent=$PARALLEL_INTENT stop_after_clean_round=$STOP_AFTER_CLEAN_ROUND"

  while true; do
    if budget_exhausted; then
      log "Duration budget reached; stopping."
      break
    fi

    ROUND_INDEX=$((ROUND_INDEX + 1))
    log "=== Round $ROUND_INDEX ==="

    if [[ "$FOCUS" == "both" ]]; then
      ensure_capture_running
    fi

    local intent_rc=0 cve_rc=0
    local -a phases=()

    if [[ "$FOCUS" == "intent" || "$FOCUS" == "both" ]]; then
      if [[ "$SKIP_INTENT" -eq 1 ]]; then
        log "Skipping intent legs (--skip-intent). Intent injection requires EDAMAME_LLM_API_KEY."
      else
        phases+=("intent")
        if ! run_intent_suite; then intent_rc=1; ANY_FAILURE=1; fi
        if [[ "$intent_rc" -ne 0 ]]; then
          warn "Intent leg failures recorded for round ${ROUND_INDEX}. Logs: $REPORT_DIR/round_${ROUND_INDEX}_*.log diag: *_diag.json"
        fi
      fi
    fi

    if [[ "$FOCUS" == "cve" || "$FOCUS" == "both" ]]; then
      phases+=("cve")
      if ! run_cve_suite; then cve_rc=1; ANY_FAILURE=1; fi
    fi

    local round_clean=0
    if [[ "$intent_rc" -eq 0 && "$cve_rc" -eq 0 ]]; then
      round_clean=1
    fi

    local snap
    snap="$(merge_snapshot_json "round_${ROUND_INDEX}_end")"
    append_jsonl "$snap"

    phases_json="$(printf '%s\n' "${phases[@]}" | python3 -c "import json,sys; print(json.dumps([x.strip() for x in sys.stdin.read().splitlines() if x.strip()]))")"
    export HARNESS_PHASES_JSON="$phases_json"
    export HARNESS_ROUND="$ROUND_INDEX"
    export HARNESS_INTENT_RC="$intent_rc"
    export HARNESS_CVE_RC="$cve_rc"
    export HARNESS_ROUND_CLEAN="$round_clean"
    export HARNESS_REPORT_DIR="$REPORT_DIR"
    export HARNESS_INTENT_POLL_ATTEMPTS="$INTENT_POLL_ATTEMPTS"
    round_json="$(python3 <<'PY'
import datetime
import json
import os
from pathlib import Path

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
phases = json.loads(os.environ["HARNESS_PHASES_JSON"])
rd = Path(os.environ["HARNESS_REPORT_DIR"])
r = os.environ["HARNESS_ROUND"]
intent_agents = json.loads(os.environ.get("INTENT_AGENTS_JSON", "[]"))

intent_legs = None
intent_first_failure = None
if "intent" in phases:
    intent_legs = {}
    diag_keep = {
        "failure",
        "e2e_suite",
        "session_keys_missing",
        "expected_session_keys",
        "predictions_for_agent",
        "predictions_total",
        "contributor_row_matched",
        "contributor_count",
        "contributor_keys",
        "session_keys_present_for_agent",
        "oc_e2e_keys_present",
        "cu_e2e_keys_present",
        "e2e_marker_keys_present",
        "hint",
        "parse_error",
        "model_empty",
        "had_successful_cli_fetch",
        "poll_config",
        "strict_hash_check",
        "matched_contributor_hash_prefix",
    }
    for agent in intent_agents:
        key = agent["agent_type"]
        stats_path = rd / f"round_{r}_{key}.stats.json"
        diag_path = rd / f"round_{r}_{key}_diag.json"
        leg = {
            "log": f"round_{r}_{key}.log",
            "diag_file": f"round_{r}_{key}_diag.json",
            "stats_file": f"round_{r}_{key}.stats.json",
        }
        if stats_path.is_file():
            try:
                leg.update(json.loads(stats_path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                leg["stats_parse_error"] = True
        else:
            leg["exit"] = None
            leg["seconds"] = None
        ex = leg.get("exit")
        if ex not in (0, None) and intent_first_failure is None:
            intent_first_failure = key
        if diag_path.is_file() and diag_path.stat().st_size > 2:
            leg["diag_present"] = True
            try:
                raw_diag = json.loads(diag_path.read_text(encoding="utf-8"))
                if isinstance(raw_diag, dict):
                    leg["diag_summary"] = {k: raw_diag[k] for k in diag_keep if k in raw_diag}
            except json.JSONDecodeError as exc:
                leg["diag_summary"] = {"parse_error": str(exc)}
        else:
            leg["diag_present"] = False
        intent_legs[key] = leg

body = {
    "kind": "round",
    "round": int(os.environ["HARNESS_ROUND"]),
    "phases": phases,
    "intent_exit": int(os.environ["HARNESS_INTENT_RC"]),
    "cve_exit": int(os.environ["HARNESS_CVE_RC"]),
    "clean": os.environ.get("HARNESS_ROUND_CLEAN", "0") == "1",
    "timestamp_utc": now,
    "intent_poll_attempts_env": int(os.environ.get("HARNESS_INTENT_POLL_ATTEMPTS", "0")),
}
if intent_legs is not None:
    body["intent_legs"] = intent_legs
    body["intent_first_failure"] = intent_first_failure
print(json.dumps(body, ensure_ascii=False))
PY
)"
    unset HARNESS_PHASES_JSON HARNESS_ROUND HARNESS_INTENT_RC HARNESS_CVE_RC HARNESS_ROUND_CLEAN HARNESS_REPORT_DIR HARNESS_INTENT_POLL_ATTEMPTS
    append_jsonl "$round_json"

    if [[ "$STRICT" -eq 1 && "$ANY_FAILURE" -eq 1 ]]; then
      warn "Strict mode: stopping after failures in round $ROUND_INDEX"
      break
    fi

    if [[ "$STOP_AFTER_CLEAN_ROUND" -eq 1 && "$round_clean" -eq 1 ]]; then
      log "Stop-after-clean-round: round $ROUND_INDEX completed cleanly; stopping."
      break
    fi

    if budget_exhausted; then
      log "Duration budget reached after round $ROUND_INDEX."
      break
    fi

    if [[ "$ROUND_INTERVAL_SECONDS" -gt 0 ]]; then
      log "Sleeping ${ROUND_INTERVAL_SECONDS}s before next round"
      run_cmd sleep "$ROUND_INTERVAL_SECONDS"
    fi

    if [[ "$DRY_RUN" -eq 1 && "$ROUND_INDEX" -ge 2 ]]; then
      log "Dry-run: stopping after 2 rounds (avoid infinite loop without real time)"
      break
    fi
  done

  finalize_summary
  log "Wrote $SUMMARY_MD"
  if [[ "$ANY_FAILURE" -eq 1 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
