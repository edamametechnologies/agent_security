#!/bin/bash
# reproduce_results.sh - Rebuild public paper outputs from published result artifacts.
#
# This script is the paper-repo reproducibility entrypoint. It does not rerun the
# full live benchmark environment; instead it recomputes the public summary from
# the published NDJSON rows, regenerates the paper bundle, and reruns readiness
# and publication checks. For a fresh live rerun, use tests/benchmark/run_live_suite.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RESULTS="$REPO_DIR/artifacts/live-paper-results.ndjson"
SUMMARY="$REPO_DIR/artifacts/live-paper-summary.json"
MANIFEST="$REPO_DIR/artifacts/live-paper-manifest.json"

usage() {
    cat <<'EOF'
Usage:
  bash scripts/reproduce_results.sh [--results path] [--summary path] [--manifest path]

This script:
  1. recomputes the public benchmark summary from the published NDJSON rows,
  2. rebuilds the paper bundle and generated PDF from those artifacts,
  3. reruns arXiv readiness and publication preflight checks.

For a fresh live benchmark rerun instead of artifact-level reproduction, run:
  python3 tests/benchmark/run_live_suite.py --mode live
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --results)
            RESULTS="${2:-}"
            shift 2
            ;;
        --summary)
            SUMMARY="${2:-}"
            shift 2
            ;;
        --manifest)
            MANIFEST="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ ! -f "$RESULTS" ]; then
    echo "Missing results file: $RESULTS" >&2
    exit 1
fi

if [ ! -f "$MANIFEST" ]; then
    echo "Missing manifest file: $MANIFEST" >&2
    exit 1
fi

bash "$SCRIPT_DIR/summarize_results.sh" \
    --input "$RESULTS" \
    --output "$SUMMARY"

PAPER_RESULTS="$RESULTS" \
PAPER_SUMMARY="$SUMMARY" \
PAPER_MANIFEST="$MANIFEST" \
    bash "$SCRIPT_DIR/regen_paper.sh"

bash "$SCRIPT_DIR/arxiv_readiness_gate.sh" "$SUMMARY" "$MANIFEST"
bash "$SCRIPT_DIR/preflight_publication.sh" "$SUMMARY" "$MANIFEST"

echo ""
echo "Artifact-level paper reproduction complete."
echo "  results: $RESULTS"
echo "  summary: $SUMMARY"
echo "  manifest: $MANIFEST"
echo "  pdf: $REPO_DIR/artifacts/paper-bundle/WHITEPAPER_GENERATED.pdf"
