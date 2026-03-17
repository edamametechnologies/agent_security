#!/bin/bash
# build_paper_bundle.sh - Build arXiv companion reproducibility bundle.
set -euo pipefail

# sha256: use sha256sum on Linux, shasum on macOS
_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}

SUMMARY="${1:-artifacts/benchmark-summary.json}"
MANIFEST="${2:-artifacts/run-manifest.json}"
WHITEPAPER_SOURCE="${3:-paper/arxiv_draft.md}"
SUPPORTING_EVIDENCE_SOURCE="${PAPER_SUPPORTING_EVIDENCE:-}"
OUT_DIR="artifacts/paper-bundle"

if [ "$#" -ge 5 ]; then
    SUPPORTING_EVIDENCE_SOURCE="$4"
    OUT_DIR="$5"
elif [ "$#" -eq 4 ]; then
    OUT_DIR="$4"
fi

if [ ! -f "$SUMMARY" ]; then
    echo "Missing benchmark summary: $SUMMARY"
    exit 1
fi

if [ ! -f "$MANIFEST" ]; then
    echo "Missing run manifest: $MANIFEST"
    exit 1
fi

if [ ! -f "$WHITEPAPER_SOURCE" ]; then
    echo "Missing whitepaper source: $WHITEPAPER_SOURCE"
    exit 1
fi

source_metrics_start_count=$(awk '/<!-- AUTO_METRICS_START -->/{c++} END{print c+0}' "$WHITEPAPER_SOURCE")
source_metrics_end_count=$(awk '/<!-- AUTO_METRICS_END -->/{c++} END{print c+0}' "$WHITEPAPER_SOURCE")
if [ "$source_metrics_start_count" -ne 1 ] || [ "$source_metrics_end_count" -ne 1 ]; then
    echo "Whitepaper source must contain exactly one AUTO_METRICS_START/END marker pair: $WHITEPAPER_SOURCE"
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

_relpath() {
    python3 -c "import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))" "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" "$REPO_ROOT"
}

REL_SUMMARY="$(_relpath "$SUMMARY")"
REL_MANIFEST="$(_relpath "$MANIFEST")"
REL_WHITEPAPER="$(_relpath "$WHITEPAPER_SOURCE")"
REL_OUT_DIR="$(_relpath "$OUT_DIR")"

mkdir -p "$OUT_DIR"

total_runs=$(jq -r '.total_runs' "$SUMMARY")
precision=$(jq -r '.precision' "$SUMMARY")
recall=$(jq -r '.recall' "$SUMMARY")
precision_ci_low=$(jq -r '.precision_ci95.low' "$SUMMARY")
precision_ci_high=$(jq -r '.precision_ci95.high' "$SUMMARY")
recall_ci_low=$(jq -r '.recall_ci95.low' "$SUMMARY")
recall_ci_high=$(jq -r '.recall_ci95.high' "$SUMMARY")
median_latency=$(jq -r '.median_latency_ms' "$SUMMARY")
p95_latency=$(jq -r '.p95_latency_ms' "$SUMMARY")
# Some protocols do not exercise rollback; render null as N/A for publishing.
rollback_reliability=$(jq -r 'if .rollback_reliability == null then "N/A" else (.rollback_reliability|tostring) end' "$SUMMARY")
precision_stddev=$(jq -r '.stability.precision_stddev' "$SUMMARY")
recall_stddev=$(jq -r '.stability.recall_stddev' "$SUMMARY")
mode=$(jq -r '.mode' "$MANIFEST")
benchmark_mode=$(jq -r '.benchmark_mode // "unknown"' "$MANIFEST")
suggested_repro_cmd="./reproduce.sh"
if [[ "$mode" == live* ]]; then
  suggested_repro_cmd="./reproduce_live.sh"
fi

cat > "$OUT_DIR/appendix-metrics.md" <<EOF
## Appendix A - Automated Benchmark Metrics

| Metric | Value |
|---|---|
| Total runs | $total_runs |
| Precision | $precision |
| Recall | $recall |
| Precision CI95 | [$precision_ci_low, $precision_ci_high] |
| Recall CI95 | [$recall_ci_low, $recall_ci_high] |
| Median latency (ms) | $median_latency |
| p95 latency (ms) | $p95_latency |
| Rollback reliability | $rollback_reliability |
| Stability (precision stddev) | $precision_stddev |
| Stability (recall stddev) | $recall_stddev |
EOF

awk '
  BEGIN { refs=0 }
  /^## References/ { refs=1; print; next }
  refs == 1 { print }
' "$WHITEPAPER_SOURCE" > "$OUT_DIR/reference-sources.txt"

refs_checksum=$(_sha256 "$OUT_DIR/reference-sources.txt" | awk "{print \$1}")

cat > "$OUT_DIR/reference-checksum.txt" <<EOF
references_sha256=$refs_checksum
source_file=$REL_WHITEPAPER
generated_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

awk '
  BEGIN { in_block=0 }
  /<!-- AUTO_METRICS_START -->/ {
    print;
    print "| Metric | Value |";
    print "|---|---|";
    print "| Total runs | " TOTAL_RUNS " |";
    print "| Precision | " PRECISION " |";
    print "| Recall | " RECALL " |";
    print "| Precision CI95 | [" PRECISION_CI_LOW ", " PRECISION_CI_HIGH "] |";
    print "| Recall CI95 | [" RECALL_CI_LOW ", " RECALL_CI_HIGH "] |";
    print "| Median latency (ms) | " MEDIAN_LATENCY " |";
    print "| p95 latency (ms) | " P95_LATENCY " |";
    print "| Rollback reliability | " ROLLBACK_RELIABILITY " |";
    print "| Stability (precision stddev) | " PRECISION_STDDEV " |";
    print "| Stability (recall stddev) | " RECALL_STDDEV " |";
    in_block=1;
    next
  }
  /<!-- AUTO_METRICS_END -->/ {
    in_block=0;
    print;
    next
  }
  in_block == 0 { print }
' TOTAL_RUNS="$total_runs" \
  PRECISION="$precision" \
  RECALL="$recall" \
  PRECISION_CI_LOW="$precision_ci_low" \
  PRECISION_CI_HIGH="$precision_ci_high" \
  RECALL_CI_LOW="$recall_ci_low" \
  RECALL_CI_HIGH="$recall_ci_high" \
  MEDIAN_LATENCY="$median_latency" \
  P95_LATENCY="$p95_latency" \
  ROLLBACK_RELIABILITY="$rollback_reliability" \
  PRECISION_STDDEV="$precision_stddev" \
  RECALL_STDDEV="$recall_stddev" \
  "$WHITEPAPER_SOURCE" > "$OUT_DIR/WHITEPAPER_GENERATED.md"

python3 - "$OUT_DIR/WHITEPAPER_GENERATED.md" \
  "$total_runs" "$precision" "$recall" \
  "$precision_ci_low" "$precision_ci_high" \
  "$recall_ci_low" "$recall_ci_high" \
  "$median_latency" "$p95_latency" \
  "$rollback_reliability" "$precision_stddev" "$recall_stddev" <<'PY'
import sys

path = sys.argv[1]
expected_rows = [
    "| Metric | Value |",
    "|---|---|",
    f"| Total runs | {sys.argv[2]} |",
    f"| Precision | {sys.argv[3]} |",
    f"| Recall | {sys.argv[4]} |",
    f"| Precision CI95 | [{sys.argv[5]}, {sys.argv[6]}] |",
    f"| Recall CI95 | [{sys.argv[7]}, {sys.argv[8]}] |",
    f"| Median latency (ms) | {sys.argv[9]} |",
    f"| p95 latency (ms) | {sys.argv[10]} |",
    f"| Rollback reliability | {sys.argv[11]} |",
    f"| Stability (precision stddev) | {sys.argv[12]} |",
    f"| Stability (recall stddev) | {sys.argv[13]} |",
]

text = open(path, encoding="utf-8").read()
start = "<!-- AUTO_METRICS_START -->"
end = "<!-- AUTO_METRICS_END -->"
start_count = text.count(start)
end_count = text.count(end)
if start_count != 1 or end_count != 1:
    raise SystemExit(
        f"Generated whitepaper must contain exactly one AUTO_METRICS marker pair "
        f"(start={start_count}, end={end_count})"
    )

start_idx = text.index(start) + len(start)
end_idx = text.index(end)
if start_idx >= end_idx:
    raise SystemExit("AUTO_METRICS marker order invalid in generated whitepaper")

block_lines = [line.strip() for line in text[start_idx:end_idx].splitlines() if line.strip()]
missing = [row for row in expected_rows if row not in block_lines]
if missing:
    raise SystemExit(
        "Generated metrics block is missing expected rows: "
        + "; ".join(missing)
    )
PY

cat > "$OUT_DIR/reproducibility-report.md" <<EOF
# Reproducibility Report

- Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Git SHA: $(jq -r '.git_sha' "$MANIFEST")
- Scenario set version: $(jq -r '.scenario_set_version' "$MANIFEST")
- Mode: $(jq -r '.mode' "$MANIFEST")
- Benchmark mode: $benchmark_mode
- Seed: $(jq -r '.seed' "$MANIFEST")
- Iterations: $(jq -r '.iterations' "$MANIFEST")

## Input Artifacts

- Benchmark summary: \`$REL_SUMMARY\`
- Run manifest: \`$REL_MANIFEST\`
- Whitepaper source: \`$REL_WHITEPAPER\`
- Supporting evidence source: \`${SUPPORTING_EVIDENCE_SOURCE:+$(_relpath "$SUPPORTING_EVIDENCE_SOURCE")}${SUPPORTING_EVIDENCE_SOURCE:-none (public bundle mode)}\`

## Suggested Reproduction Commands

\`\`\`bash
$suggested_repro_cmd
\`\`\`

## Checksums

\`\`\`
$(_sha256 "$SUMMARY" | awk -v rp="$REL_SUMMARY" '{print $1 "  " rp}')
$(_sha256 "$MANIFEST" | awk -v rp="$REL_MANIFEST" '{print $1 "  " rp}')
$(_sha256 "$WHITEPAPER_SOURCE" | awk -v rp="$REL_WHITEPAPER" '{print $1 "  " rp}')
$( [ -n "$SUPPORTING_EVIDENCE_SOURCE" ] && [ -f "$SUPPORTING_EVIDENCE_SOURCE" ] && _sha256 "$SUPPORTING_EVIDENCE_SOURCE" | awk -v rp="$(_relpath "$SUPPORTING_EVIDENCE_SOURCE")" '{print $1 "  " rp}' || true )
\`\`\`
EOF

REL_EVIDENCE_JSON="null"
if [ -n "$SUPPORTING_EVIDENCE_SOURCE" ]; then
  REL_EVIDENCE_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$(_relpath "$SUPPORTING_EVIDENCE_SOURCE")")"
fi

cat > "$OUT_DIR/bundle-index.json" <<EOF
{
  "generated_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "inputs": {
    "benchmark_summary": "$REL_SUMMARY",
    "run_manifest": "$REL_MANIFEST",
    "whitepaper_source": "$REL_WHITEPAPER",
    "supporting_evidence_source": $REL_EVIDENCE_JSON
  },
  "outputs": {
    "appendix_metrics": "$REL_OUT_DIR/appendix-metrics.md",
    "reference_sources": "$REL_OUT_DIR/reference-sources.txt",
    "reference_checksum": "$REL_OUT_DIR/reference-checksum.txt",
    "whitepaper_generated": "$REL_OUT_DIR/WHITEPAPER_GENERATED.md",
    "reproducibility_report": "$REL_OUT_DIR/reproducibility-report.md"
  }
}
EOF

echo "Paper bundle created in: $OUT_DIR"
