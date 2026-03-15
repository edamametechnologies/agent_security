#!/bin/bash
# record_result.sh - Append one benchmark run result to NDJSON.
#
# Usage:
#   ./tests/benchmark/record_result.sh \
#     --scenario tests/benchmark/scenarios/benign-maintenance.json \
#     --observed-class benign \
#     --observed-divergence false \
#     --latency-ms 1200 \
#     --seed 42 \
#     --runner github-actions \
#     --git-sha abcdef1 \
#     --scenario-set-version v1 \
#     --output artifacts/benchmark-results.ndjson
set -euo pipefail

SCENARIO=""
OBSERVED_CLASS=""
OBSERVED_DIVERGENCE=""
LATENCY_MS=""
OUTPUT="artifacts/benchmark-results.ndjson"
OPERATOR_DECISION="none"
UNDO_RESULT="not_applicable"
TRACE_DIR=""
SEED="0"
RUNNER="local"
GIT_SHA="unknown"
SCENARIO_SET_VERSION="unknown"
RUN_ID="unknown"
MODE="unknown"
POLICY="primary"

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario) SCENARIO="${2:-}"; shift 2 ;;
        --observed-class) OBSERVED_CLASS="${2:-}"; shift 2 ;;
        --observed-divergence) OBSERVED_DIVERGENCE="${2:-}"; shift 2 ;;
        --latency-ms) LATENCY_MS="${2:-}"; shift 2 ;;
        --output) OUTPUT="${2:-}"; shift 2 ;;
        --operator-decision) OPERATOR_DECISION="${2:-}"; shift 2 ;;
        --undo-result) UNDO_RESULT="${2:-}"; shift 2 ;;
        --trace-dir) TRACE_DIR="${2:-}"; shift 2 ;;
        --seed) SEED="${2:-}"; shift 2 ;;
        --runner) RUNNER="${2:-}"; shift 2 ;;
        --git-sha) GIT_SHA="${2:-}"; shift 2 ;;
        --scenario-set-version) SCENARIO_SET_VERSION="${2:-}"; shift 2 ;;
        --run-id) RUN_ID="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --policy) POLICY="${2:-}"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$SCENARIO" ] || [ -z "$OBSERVED_CLASS" ] || [ -z "$OBSERVED_DIVERGENCE" ] || [ -z "$LATENCY_MS" ]; then
    echo "Missing required arguments."
    exit 1
fi

if [ ! -f "$SCENARIO" ]; then
    echo "Scenario file not found: $SCENARIO"
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

scenario_id=$(jq -r '.id' "$SCENARIO")
category=$(jq -r '.category' "$SCENARIO")
expected_class=$(jq -r '.expected_class' "$SCENARIO")
expected_divergence=$(jq -r '.expected_divergence' "$SCENARIO")
intent=$(jq -r '.intent' "$SCENARIO")
cve_ids=$(jq -c '.cve_ids // []' "$SCENARIO")

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -nc \
  --arg ts "$timestamp" \
  --arg sid "$scenario_id" \
  --arg cat "$category" \
  --arg intent "$intent" \
  --arg expc "$expected_class" \
  --argjson expd "$expected_divergence" \
  --argjson cves "$cve_ids" \
  --arg obsc "$OBSERVED_CLASS" \
  --argjson obsd "$OBSERVED_DIVERGENCE" \
  --argjson lat "$LATENCY_MS" \
  --arg op "$OPERATOR_DECISION" \
  --arg undo "$UNDO_RESULT" \
  --arg trace_dir "$TRACE_DIR" \
  --arg seed "$SEED" \
  --arg runner "$RUNNER" \
  --arg git_sha "$GIT_SHA" \
  --arg scenario_set_version "$SCENARIO_SET_VERSION" \
  --arg run_id "$RUN_ID" \
  --arg mode "$MODE" \
  --arg policy "$POLICY" \
  '{
    timestamp_utc: $ts,
    run: {
      id: $run_id,
      mode: $mode,
      benchmark_mode: "live",
      policy: $policy,
      seed: $seed,
      runner: $runner,
      git_sha: $git_sha,
      scenario_set_version: $scenario_set_version
    },
    scenario_id: $sid,
    category: $cat,
    declared_intent: $intent,
    cve_ids: $cves,
    expected_class: $expc,
    expected_divergence: $expd,
    observed_class: $obsc,
    observed_divergence: $obsd,
    detection_latency_ms: $lat,
    operator_decision: $op,
    undo_result: $undo,
    trace_dir: (if $trace_dir == "" then null else $trace_dir end)
  }' >> "$OUTPUT"

echo "Appended benchmark result: $scenario_id -> $OUTPUT"
