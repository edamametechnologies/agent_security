#!/bin/bash
# arxiv_readiness_gate.sh - Compute arXiv readiness scorecard from live data.
#
# All criteria are evaluated against trace-backed live benchmark results.
# Synthetic/replay data is not accepted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_SUMMARY_DEFAULT="$REPO_DIR/artifacts/live-paper-summary.json"
LOCAL_MANIFEST_DEFAULT="$REPO_DIR/artifacts/live-paper-manifest.json"

SUMMARY="${1:-$LOCAL_SUMMARY_DEFAULT}"
MANIFEST="${2:-$LOCAL_MANIFEST_DEFAULT}"
REPORT_MD="${3:-$REPO_DIR/artifacts/arxiv-readiness-scorecard.md}"
REPORT_JSON="${4:-$REPO_DIR/artifacts/arxiv-readiness-scorecard.json}"
ENFORCE="${ENFORCE_ARXIV_GATE:-false}"

required_files=("$SUMMARY" "$MANIFEST")
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Missing required file for readiness gate: $file"
        exit 1
    fi
done

mkdir -p "$(dirname "$REPORT_MD")" "$(dirname "$REPORT_JSON")"

jq -n \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --slurpfile summary "$SUMMARY" \
  --slurpfile manifest "$MANIFEST" \
  '
  ($manifest[0].mode // "unknown") as $mode
  | ($summary[0].total_runs // 0) as $total_runs
  | ($summary[0].precision_ci95.low // null) as $precision_ci_low
  | ($summary[0].recall_ci95.low // null) as $recall_ci_low
  | ($summary[0].stability.seeds_evaluated // 0) as $seeds
  | ($summary[0].stability.recall_stddev // null) as $recall_stddev
  | ($summary[0].precision // null) as $precision
  | ($summary[0].recall // null) as $recall
  | ($manifest[0].benchmark_mode // "unknown") as $benchmark_mode
  | ($manifest[0].counts.total_planned_runs // (($manifest[0].iterations // 0) * ($manifest[0].scenario_count // 0))) as $planned_runs
  | ($manifest[0].counts.valid_runs // $planned_runs) as $valid_runs
  | ($manifest[0].counts.skipped_runs // 0) as $skipped_runs
  | (if $planned_runs > 0 then ($skipped_runs / $planned_runs) else null end) as $skipped_ratio
  | ($manifest[0].scenario_count // 0) as $scenario_count
  | (($manifest[0].runs // []) | map(.scenario_id) | unique | length) as $covered_scenarios
  | (if $scenario_count > 0 then ($covered_scenarios / $scenario_count) else null end) as $scenario_coverage_ratio
  | ($manifest[0].group_count // 0) as $group_count
  | (($manifest[0].runs // []) | map(.group_id) | unique | length) as $covered_groups
  | (if $group_count > 0 then ($covered_groups / $group_count) else null end) as $group_coverage_ratio
  | (($summary[0].categories // []) | length) as $category_count
  | (($summary[0].by_benchmark_mode // []) | map(select((.benchmark_mode // "unknown") == "unknown")) | length) as $unknown_benchmark_rows
  | [
      {
        id: "live_mode",
        description: "Benchmark mode is live (trace-backed, not synthetic)",
        passed: ($mode == "live"),
        observed: $mode,
        threshold: "== live",
        severity: "high"
      },
      {
        id: "reproducibility_manifest",
        description: "Manifest includes git SHA and scenario-set hash",
        passed: (($manifest[0].git_sha != "unknown") and ($manifest[0].scenario_set_version != "unknown")),
        observed: {git_sha: $manifest[0].git_sha, scenario_set_version: $manifest[0].scenario_set_version},
        threshold: "git_sha != unknown AND scenario_set_version != unknown",
        severity: "high"
      },
      {
        id: "manifest_benchmark_mode_explicit",
        description: "Manifest benchmark_mode is explicit (not unknown)",
        passed: ($benchmark_mode != "unknown"),
        observed: $benchmark_mode,
        threshold: "!= unknown",
        severity: "high"
      },
      {
        id: "summary_benchmark_modes_explicit",
        description: "Summary has no unknown benchmark_mode rows",
        passed: ($unknown_benchmark_rows == 0),
        observed: $unknown_benchmark_rows,
        threshold: "== 0",
        severity: "high"
      },
      {
        id: "summary_manifest_run_consistency",
        description: "Summary total_runs matches manifest valid_runs",
        passed: ($total_runs == $valid_runs),
        observed: {summary_total_runs: $total_runs, manifest_valid_runs: $valid_runs},
        threshold: "summary.total_runs == manifest.counts.valid_runs",
        severity: "high"
      },
      {
        id: "sample_size",
        description: "At least 100 total measured runs",
        passed: ($total_runs >= 100),
        observed: $total_runs,
        threshold: ">= 100",
        severity: "high"
      },
      {
        id: "precision_lower_bound",
        description: "Precision CI95 lower bound >= 0.85",
        passed: (($precision_ci_low != null) and ($precision_ci_low >= 0.85)),
        observed: $precision_ci_low,
        threshold: ">= 0.85",
        severity: "high"
      },
      {
        id: "recall_lower_bound",
        description: "Recall CI95 lower bound >= 0.85",
        passed: (($recall_ci_low != null) and ($recall_ci_low >= 0.85)),
        observed: $recall_ci_low,
        threshold: ">= 0.85",
        severity: "high"
      },
      {
        id: "seed_coverage",
        description: "At least 10 distinct seeds",
        passed: ($seeds >= 10),
        observed: $seeds,
        threshold: ">= 10",
        severity: "medium"
      },
      {
        id: "skip_ratio",
        description: "Skipped-run ratio <= 15%",
        passed: (($skipped_ratio != null) and ($skipped_ratio <= 0.15)),
        observed: {skipped_runs: $skipped_runs, planned_runs: $planned_runs, skipped_ratio: $skipped_ratio},
        threshold: "<= 0.15",
        severity: "high"
      },
      {
        id: "scenario_coverage",
        description: "Scenario coverage ratio >= 80%",
        passed: (($scenario_coverage_ratio != null) and ($scenario_coverage_ratio >= 0.80)),
        observed: {covered_scenarios: $covered_scenarios, scenario_count: $scenario_count, coverage_ratio: $scenario_coverage_ratio},
        threshold: ">= 0.80",
        severity: "high"
      },
      {
        id: "group_coverage",
        description: "Scenario-group coverage ratio >= 70%",
        passed: (($group_coverage_ratio != null) and ($group_coverage_ratio >= 0.70)),
        observed: {covered_groups: $covered_groups, group_count: $group_count, coverage_ratio: $group_coverage_ratio},
        threshold: ">= 0.70",
        severity: "medium"
      },
      {
        id: "category_diversity",
        description: "At least 5 evaluated categories",
        passed: ($category_count >= 5),
        observed: $category_count,
        threshold: ">= 5",
        severity: "high"
      },
      {
        id: "stability_recall_stddev",
        description: "Recall stddev across seeds <= 0.15",
        passed: (($recall_stddev != null) and ($recall_stddev <= 0.15)),
        observed: $recall_stddev,
        threshold: "<= 0.15",
        severity: "high"
      }
    ] as $criteria
  | {
      generated_at_utc: $generated_at,
      verdict: (
        if ($criteria | map(select(.severity == "high" and .passed == false)) | length) > 0
        then "NO_GO"
        elif ($criteria | map(select(.passed == false)) | length) > 0
        then "CONDITIONAL_GO"
        else "GO"
        end
      ),
      evidence_source: {
        mode: $mode,
        benchmark_mode: $benchmark_mode,
        total_runs: $total_runs,
        precision: $precision,
        recall: $recall,
        seeds: $seeds,
        skipped_ratio: $skipped_ratio,
        scenario_coverage_ratio: $scenario_coverage_ratio,
        group_coverage_ratio: $group_coverage_ratio,
        category_count: $category_count,
        unknown_benchmark_rows: $unknown_benchmark_rows,
        manifest_valid_runs: $valid_runs,
        git_sha: $manifest[0].git_sha
      },
      criteria: $criteria,
      stats: {
        total: ($criteria | length),
        passed: ($criteria | map(select(.passed == true)) | length),
        failed: ($criteria | map(select(.passed == false)) | length),
        failed_high: ($criteria | map(select(.severity == "high" and .passed == false)) | length)
      }
    }' > "$REPORT_JSON"

jq -r '
  "# ArXiv Readiness Scorecard\n\n" +
  "- Generated at: " + .generated_at_utc + "\n" +
  "- Verdict: **" + .verdict + "**\n" +
  "- Source: " + .evidence_source.mode + " (" + (.evidence_source.total_runs|tostring) + " runs, " + (.evidence_source.seeds|tostring) + " seeds)\n" +
  "- Passed: " + (.stats.passed|tostring) + "/" + (.stats.total|tostring) + "\n\n" +
  "| Criterion | Severity | Threshold | Observed | Status |\n" +
  "|---|---|---|---|---|\n" +
  (.criteria | map(
    "| " + .description + " | " + .severity + " | `" + (.threshold|tostring) + "` | `" + (.observed|tostring) + "` | " + (if .passed then "PASS" else "FAIL" end) + " |"
  ) | join("\n")) + "\n"
' "$REPORT_JSON" > "$REPORT_MD"

echo "Wrote arXiv readiness reports:"
echo "  $REPORT_JSON"
echo "  $REPORT_MD"

if [ "$ENFORCE" = "true" ]; then
    verdict="$(jq -r '.verdict' "$REPORT_JSON")"
    if [ "$verdict" = "NO_GO" ]; then
        echo "ArXiv readiness enforce mode: NO_GO"
        exit 1
    fi
fi
