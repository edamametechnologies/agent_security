#!/bin/bash
# preflight_publication.sh - Validate publication lineage against canonical artifacts.
#
# Usage:
#   ./scripts/preflight_publication.sh \
#     [summary.json] [manifest.json] [scorecard.json] [paper.md] \
#     [claim_index.md]
#
# Defaults:
#   artifacts/live-paper-summary.json
#   artifacts/live-paper-manifest.json
#   artifacts/arxiv-readiness-scorecard.json
#   paper/arxiv_draft.md
#   docs/CLAIM_ARTIFACT_INDEX.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
README_FILE="$REPO_DIR/README.md"
LOCAL_SUMMARY_DEFAULT="$REPO_DIR/artifacts/live-paper-summary.json"
LOCAL_MANIFEST_DEFAULT="$REPO_DIR/artifacts/live-paper-manifest.json"
REVIEW_RENDERER="${REVIEW_RENDERER:-}"
REVIEW_OUT_DIR="$REPO_DIR/paper/pdf-pages/review"
REVIEW_INDEX="$REVIEW_OUT_DIR/review-index.json"
PDF_BUILD_LOG="$REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.build.log"

SUMMARY="${1:-$LOCAL_SUMMARY_DEFAULT}"
MANIFEST="${2:-$LOCAL_MANIFEST_DEFAULT}"
SCORECARD="${3:-$REPO_DIR/artifacts/arxiv-readiness-scorecard.json}"
PAPER="${4:-$REPO_DIR/paper/arxiv_draft.md}"
CLAIM_INDEX="${5:-$REPO_DIR/docs/CLAIM_ARTIFACT_INDEX.md}"

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

run_figure_audit() {
    local audit_output=""
    local review_ok="false"
    local numbering_ok="false"
    local page_layout_ok="false"
    local audit_failures=""

    if [ -z "$REVIEW_RENDERER" ] || [ ! -f "$REVIEW_RENDERER" ]; then
        echo "WARN: Figure audit renderer not available (set REVIEW_RENDERER env var); skipping figure audit."
        return
    fi

    if ! audit_output="$(
        python3 "$REVIEW_RENDERER" \
            --draft "$PAPER" \
            --pdf "$REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.pdf" \
            --figures-dir "$REPO_DIR/paper/figures" \
            --out-dir "$REVIEW_OUT_DIR" 2>&1
    )"; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            add_error "Figure audit failed: $line"
        done <<< "$audit_output"
        return
    fi

    if [ ! -f "$REVIEW_INDEX" ]; then
        add_error "Figure audit did not produce review index: $REVIEW_INDEX"
        return
    fi

    review_ok="$(jq -r '.review_ok // false' "$REVIEW_INDEX" 2>/dev/null || echo false)"
    numbering_ok="$(jq -r '.numbering_ok // false' "$REVIEW_INDEX" 2>/dev/null || echo false)"
    page_layout_ok="$(jq -r '.page_layout_ok // false' "$REVIEW_INDEX" 2>/dev/null || echo false)"

    if [ "$review_ok" != "true" ]; then
        audit_failures="$(jq -r '.failures[]?' "$REVIEW_INDEX" 2>/dev/null || true)"
        if [ -n "$audit_failures" ]; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                add_error "Figure audit: $line"
            done <<< "$audit_failures"
        else
            add_error "Figure audit failed: review_ok != true in $REVIEW_INDEX"
        fi
    fi

    if [ "$numbering_ok" != "true" ]; then
        add_error "Figure audit failed: numbering_ok != true in $REVIEW_INDEX"
    fi
    if [ "$page_layout_ok" != "true" ]; then
        add_error "Figure audit failed: page_layout_ok != true in $REVIEW_INDEX"
    fi
}

run_pdf_build_log_audit() {
    local overflow_hits=""

    if [ ! -f "$PDF_BUILD_LOG" ]; then
        add_error "Missing PDF build log: $PDF_BUILD_LOG"
        return
    fi

    overflow_hits="$(grep -En 'Overfull \\hbox|Overfull \\vbox|Float too large for page' "$PDF_BUILD_LOG" || true)"
    if [ -n "$overflow_hits" ]; then
        add_error "PDF build log contains layout overflows: $(echo "$overflow_hits" | tr '\n' '; ')"
    fi
}

require_file "$SUMMARY"
require_file "$MANIFEST"
require_file "$SCORECARD"
require_file "$PAPER"
require_file "$CLAIM_INDEX"
require_file "$README_FILE"
require_file "$REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.md"
require_file "$REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.tex"
require_file "$REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.pdf"
require_file "$PDF_BUILD_LOG"
print_errors_and_exit

run_figure_audit
run_pdf_build_log_audit

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
assert_absent_pattern "private evidence doc leak in paper" 'CREDIBILITY_EVIDENCE|SOUNDNESS_ANALYSIS' "$PAPER"
assert_absent_pattern "private evidence doc leak in README" 'CREDIBILITY_EVIDENCE|SOUNDNESS_ANALYSIS' "$README_FILE"
assert_absent_pattern "private evidence doc leak in reproducibility report" 'CREDIBILITY_EVIDENCE|SOUNDNESS_ANALYSIS' "$REPO_DIR/artifacts/paper-bundle/reproducibility-report.md"
assert_absent_pattern "private evidence doc leak in bundle index" 'CREDIBILITY_EVIDENCE|SOUNDNESS_ANALYSIS' "$REPO_DIR/artifacts/paper-bundle/bundle-index.json"
assert_present_pattern "claim index citation" 'CLAIM_ARTIFACT_INDEX\.md' "$PAPER"
assert_present_pattern "paper repo citation" 'edamametechnologies/agent_security' "$PAPER"
assert_present_pattern "paper OpenClaw package citation" 'edamametechnologies/edamame_openclaw' "$PAPER"
assert_present_pattern "paper Cursor package citation" 'edamametechnologies/edamame_cursor' "$PAPER"
assert_present_pattern "README OpenClaw package link" 'edamametechnologies/edamame_openclaw' "$README_FILE"
assert_present_pattern "README Cursor package link" 'edamametechnologies/edamame_cursor' "$README_FILE"
assert_present_pattern "README generated PDF link" 'WHITEPAPER_GENERATED\.pdf' "$README_FILE"

metadata_errors="$(python3 - "$CLAIM_INDEX" "$PAPER" "$manifest_run_id" "$manifest_git_sha" "$manifest_scenario_set_version" "$manifest_mode" "$manifest_benchmark_mode" <<'PY'
import re
import sys

claim_index = open(sys.argv[1], encoding="utf-8").read()
paper = open(sys.argv[2], encoding="utf-8").read()
run_id, git_sha, scenario_set_version, mode, benchmark_mode = sys.argv[3:8]

def paper_has_bound_metadata(key: str, value: str) -> bool:
    escaped_value = re.escape(value)
    full_pattern = rf"`?{re.escape(key)}`?\s*:\s*`{escaped_value}`"
    if re.search(full_pattern, paper):
        return True
    if key == "scenario_set_version":
        prefix_pattern = rf"`?{re.escape(key)}`?\s*:\s*`{re.escape(value[:16])}\.\.\.`"
        return re.search(prefix_pattern, paper) is not None
    return False

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
    if not paper_has_bound_metadata(key, value):
        print(f"Paper missing bound metadata entry for {key}={value}")
PY
)"
if [ -n "$metadata_errors" ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        add_error "$line"
    done <<< "$metadata_errors"
fi

print_errors_and_exit

echo "Publication preflight passed."
echo "  summary: $SUMMARY"
echo "  manifest: $MANIFEST"
echo "  scorecard: $SCORECARD"
echo "  paper: $PAPER"
echo "  claim_index: $CLAIM_INDEX"
