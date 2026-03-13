#!/bin/bash
# preflight_publication.sh - Validate publication/demo lineage against canonical artifacts.
#
# Usage:
#   ./scripts/preflight_publication.sh \
#     [summary.json] [manifest.json] [scorecard.json] [paper.md] \
#     [claim_index.md] [demo_spec.md] [scenario_map.json]
#
# Defaults:
#   artifacts/live-paper-summary.json
#   artifacts/live-paper-manifest.json
#   artifacts/arxiv-readiness-scorecard.json
#   paper/arxiv_draft.md
#   docs/CLAIM_ARTIFACT_INDEX.md
#   docs/DEMO_SPEC.md
#   demo/exec_scenario_cve_map.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENCLAW_DIR="$REPO_DIR/../openclaw_security"

SUMMARY="${1:-$OPENCLAW_DIR/artifacts/live-paper-summary.json}"
MANIFEST="${2:-$OPENCLAW_DIR/artifacts/live-paper-manifest.json}"
SCORECARD="${3:-$REPO_DIR/artifacts/arxiv-readiness-scorecard.json}"
PAPER="${4:-$REPO_DIR/paper/arxiv_draft.md}"
CLAIM_INDEX="${5:-$REPO_DIR/docs/CLAIM_ARTIFACT_INDEX.md}"
DEMO_SPEC="${6:-$OPENCLAW_DIR/docs/DEMO_SPEC.md}"
SCENARIO_MAP="${7:-$OPENCLAW_DIR/demo/exec_scenario_cve_map.json}"
SUMMARY_ALT="$OPENCLAW_DIR/artifacts/live-paper-new-summary.json"
MANIFEST_ALT="$OPENCLAW_DIR/artifacts/live-paper-new-manifest.json"
DEMO_PPTX="$OPENCLAW_DIR/demo/OpenClaw-Exec-Demo-Architecture-2026.pptx"
DEMO_README="$OPENCLAW_DIR/demo/OpenClaw-Exec-Demo-Architecture-2026-README.md"
DEMO_PROOF="$OPENCLAW_DIR/demo/OpenClaw-Exec-Demo-Architecture-2026-proof.json"
DEMO_COMPANION="$OPENCLAW_DIR/demo/OpenClaw-Exec-Demo-Architecture-2026-Companion.md"

if [ "$SUMMARY" = "artifacts/live-paper-summary.json" ] && [ ! -f "$SUMMARY" ] && [ -f "$SUMMARY_ALT" ]; then
    SUMMARY="$SUMMARY_ALT"
fi
if [ "$MANIFEST" = "artifacts/live-paper-manifest.json" ] && [ ! -f "$MANIFEST" ] && [ -f "$MANIFEST_ALT" ]; then
    MANIFEST="$MANIFEST_ALT"
fi

declare -a ERRORS=()

add_error() {
    ERRORS+=("$1")
}

require_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        add_error "Missing required file: $file"
    fi
}

assert_string_equal() {
    local label="$1"
    local expected="$2"
    local observed="$3"
    if [ "$expected" != "$observed" ]; then
        add_error "$label mismatch (expected='$expected', observed='$observed')"
    fi
}

assert_number_equal() {
    local label="$1"
    local expected="$2"
    local observed="$3"

    if [ "$expected" = "null" ] && [ "$observed" = "null" ]; then
        return
    fi

    if [ "$expected" = "null" ] || [ "$observed" = "null" ] || [ -z "$expected" ] || [ -z "$observed" ]; then
        add_error "$label missing numeric value (expected='$expected', observed='$observed')"
        return
    fi

    if ! python3 - "$expected" "$observed" <<'PY'
import math
import sys

try:
    expected = float(sys.argv[1])
    observed = float(sys.argv[2])
except Exception:
    sys.exit(2)

sys.exit(0 if math.isclose(expected, observed, rel_tol=1e-12, abs_tol=1e-12) else 1)
PY
    then
        add_error "$label mismatch (expected=$expected, observed=$observed)"
    fi
}

assert_absent_pattern() {
    local label="$1"
    local pattern="$2"
    local file="$3"
    local hits
    hits="$(grep -En "$pattern" "$file" || true)"
    if [ -n "$hits" ]; then
        add_error "$label found in $file: $(echo "$hits" | tr '\n' '; ')"
    fi
}

assert_present_pattern() {
    local label="$1"
    local pattern="$2"
    local file="$3"
    if ! grep -Eq "$pattern" "$file"; then
        add_error "$label missing in $file"
    fi
}

print_errors_and_exit() {
    if [ "${#ERRORS[@]}" -eq 0 ]; then
        return
    fi
    echo "Publication preflight FAILED (${#ERRORS[@]} issue(s)):"
    local i
    for i in "${!ERRORS[@]}"; do
        printf '  %d. %s\n' "$((i + 1))" "${ERRORS[$i]}"
    done
    exit 1
}

require_file "$SUMMARY"
require_file "$MANIFEST"
require_file "$SCORECARD"
require_file "$PAPER"
require_file "$CLAIM_INDEX"
require_file "$DEMO_SPEC"
require_file "$SCENARIO_MAP"
require_file "$DEMO_PPTX"
require_file "$DEMO_README"
require_file "$DEMO_PROOF"
require_file "$DEMO_COMPANION"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_two_plane.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_skill_call_path.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_two_cron_mermaid_sequence.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_skill_structure.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_divergence_engine_tick.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_test_architecture.png"
require_file "$OPENCLAW_DIR/demo/generated_graphics/fig_exec_scenario_cve_matrix.png"
print_errors_and_exit

summary_total_runs="$(jq -r '.total_runs // "null"' "$SUMMARY")"
summary_precision="$(jq -r '.precision // "null"' "$SUMMARY")"
summary_recall="$(jq -r '.recall // "null"' "$SUMMARY")"
summary_unknown_benchmark_rows="$(jq -r '[.by_benchmark_mode[]? | select((.benchmark_mode // "unknown") == "unknown")] | length' "$SUMMARY")"

manifest_run_id="$(jq -r '.run_id // "null"' "$MANIFEST")"
manifest_git_sha="$(jq -r '.git_sha // "null"' "$MANIFEST")"
manifest_scenario_set_version="$(jq -r '.scenario_set_version // "null"' "$MANIFEST")"
manifest_mode="$(jq -r '.mode // "null"' "$MANIFEST")"
manifest_benchmark_mode="$(jq -r '.benchmark_mode // "unknown"' "$MANIFEST")"
manifest_valid_runs="$(jq -r '.counts.valid_runs // .counts.total_planned_runs // "null"' "$MANIFEST")"

scorecard_total_runs="$(jq -r '.evidence_source.total_runs // "null"' "$SCORECARD")"
scorecard_precision="$(jq -r '.evidence_source.precision // "null"' "$SCORECARD")"
scorecard_recall="$(jq -r '.evidence_source.recall // "null"' "$SCORECARD")"
scorecard_git_sha="$(jq -r '.evidence_source.git_sha // "null"' "$SCORECARD")"

assert_number_equal "summary.total_runs vs manifest.counts.valid_runs" "$manifest_valid_runs" "$summary_total_runs"
assert_number_equal "scorecard.total_runs vs summary.total_runs" "$summary_total_runs" "$scorecard_total_runs"
assert_number_equal "scorecard.precision vs summary.precision" "$summary_precision" "$scorecard_precision"
assert_number_equal "scorecard.recall vs summary.recall" "$summary_recall" "$scorecard_recall"
assert_string_equal "scorecard.git_sha vs manifest.git_sha" "$manifest_git_sha" "$scorecard_git_sha"

if [ "$manifest_mode" != "live" ]; then
    add_error "Manifest mode must be live for publication (observed='$manifest_mode')"
fi
if [ "$manifest_benchmark_mode" = "unknown" ]; then
    add_error "Manifest benchmark_mode is unknown; expected explicit live benchmark mode"
fi
if [ "$summary_unknown_benchmark_rows" != "0" ]; then
    add_error "Summary contains unknown benchmark_mode rows; regenerate canonical summary"
fi

metrics_start_count="$(grep -Fc "<!-- AUTO_METRICS_START -->" "$PAPER" || true)"
metrics_end_count="$(grep -Fc "<!-- AUTO_METRICS_END -->" "$PAPER" || true)"
if [ "$metrics_start_count" -ne 1 ] || [ "$metrics_end_count" -ne 1 ]; then
    add_error "paper/arxiv_draft.md must contain exactly one AUTO_METRICS_START/END marker pair"
fi

assert_absent_pattern "stale model baseline (gpt-4o)" 'openai/gpt-4o' "$PAPER"
assert_absent_pattern "stale benchmark-scale wording" '50 scenarios, 8 categories|Full BadAgentUse Suite \(50 scenarios\)' "$PAPER"
assert_absent_pattern "stale demo-pack wording" '6-scenario|exec-demo-pack-[0-9]{8}T[0-9]{6}Z' "$PAPER"
assert_present_pattern "claim index citation" 'CLAIM_ARTIFACT_INDEX\.md' "$PAPER"

metadata_errors="$(python3 - "$CLAIM_INDEX" "$PAPER" "$manifest_run_id" "$manifest_git_sha" "$manifest_scenario_set_version" "$manifest_mode" "$manifest_benchmark_mode" <<'PY'
import re
import sys

claim_index = open(sys.argv[1], encoding="utf-8").read()
paper = open(sys.argv[2], encoding="utf-8").read()
run_id, git_sha, scenario_set_version, mode, benchmark_mode = sys.argv[3:8]

checks = [
    ("run_id", run_id),
    ("git_sha", git_sha),
    ("scenario_set_version", scenario_set_version),
    ("mode", mode),
]
if benchmark_mode != "unknown":
    checks.append(("benchmark_mode", benchmark_mode))

for key, value in checks:
    escaped_value = re.escape(value)
    pattern = rf"`?{re.escape(key)}`?\s*:\s*`{escaped_value}`"
    if not re.search(pattern, claim_index):
        print(f"Claim index missing bound metadata entry for {key}={value}")
    if not re.search(pattern, paper):
        print(f"Paper missing bound metadata entry for {key}={value}")
PY
)"
if [ -n "$metadata_errors" ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        add_error "$line"
    done <<< "$metadata_errors"
fi

scenario_count="$(jq -r '.scenarios | length' "$SCENARIO_MAP")"
future_ids="$(jq -r '[.scenarios[] | select((.id // "") | test("^future-")) | .id] | join(",")' "$SCENARIO_MAP")"
assert_number_equal "exec_scenario_cve_map scenario count" "8" "$scenario_count"
if [ -n "$future_ids" ]; then
    add_error "Scenario map contains standalone future-* IDs: $future_ids"
fi

assert_present_pattern "DEMO_SPEC eight-scenario contract" '8 canonical scenarios|eight canonical scenario' "$DEMO_SPEC"
assert_present_pattern "DEMO_SPEC session-history requirement" 'sessions_history' "$DEMO_SPEC"
assert_present_pattern "DEMO_SPEC one-skill architecture" 'one OpenClaw cron skill' "$DEMO_SPEC"
assert_present_pattern "DEMO_SPEC deferred lateral movement contract" 'attack-lateral-movement.*DEFERRED|Scenario 7.*deferred' "$DEMO_SPEC"

assert_absent_pattern "stale two-skill wording in graphics generator" '[Tt]wo-Skill|two-skill|two skills' "$OPENCLAW_DIR/demo/scripts/generate_exec_demo_graphics.py"
assert_absent_pattern "stale two-skill wording in deck generator" '[Tt]wo-Skill|two-skill|two skills' "$OPENCLAW_DIR/demo/scripts/build_exec_demo_pptx.py"
assert_absent_pattern "stale two-skill wording in companion generator" '[Tt]wo-Skill|two-skill|two skills' "$OPENCLAW_DIR/demo/scripts/build_exec_demo_docx.py"
assert_absent_pattern "stale two-skill wording in exec summary source" '[Tt]wo-Skill|two-skill|two skills' "$OPENCLAW_DIR/demo/exec_summary.md"
assert_absent_pattern "stale standalone posture-check wording in companion generator" 'Posture Check \(cron: hourly|independent skill,[[:space:]]*\*\*Posture Check\*\*' "$OPENCLAW_DIR/demo/scripts/build_exec_demo_docx.py"
assert_absent_pattern "stale standalone posture-check wording in generated companion" 'Posture Check \(cron: hourly|independent skill,[[:space:]]*\*\*Posture Check\*\*' "$DEMO_COMPANION"

assert_present_pattern "graphics generator LAN/open-port wording" 'LAN neighbors, host open ports' "$OPENCLAW_DIR/demo/scripts/generate_exec_demo_graphics.py"
assert_present_pattern "companion LAN/open-port wording" 'LAN neighbors, host open ports' "$DEMO_COMPANION"
assert_present_pattern "exec summary one-skill wording" 'one-skill-plus-internal-engine runtime pipeline' "$OPENCLAW_DIR/demo/exec_summary.md"

print_errors_and_exit

echo "Publication preflight passed."
echo "  summary: $SUMMARY"
echo "  manifest: $MANIFEST"
echo "  scorecard: $SCORECARD"
echo "  paper: $PAPER"
echo "  claim_index: $CLAIM_INDEX"
echo "  demo_spec: $DEMO_SPEC"
echo "  scenario_map: $SCENARIO_MAP"
