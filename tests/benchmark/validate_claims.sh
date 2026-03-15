#!/bin/bash
# validate_claims.sh - Fail when efficacy claims exceed measured evidence.
#
# Default policy:
# - if evidence gate is not met, forbid strong efficacy claim patterns
#   in public-facing documents.
set -euo pipefail

SUMMARY="artifacts/benchmark-summary.json"
TARGETS=("README.md" "paper/arxiv_draft.md")
MIN_RUNS="${CLAIMS_MIN_RUNS:-30}"
MIN_PRECISION="${CLAIMS_MIN_PRECISION:-0.80}"
MIN_RECALL="${CLAIMS_MIN_RECALL:-0.80}"

while [ $# -gt 0 ]; do
    case "$1" in
        --summary) SUMMARY="${2:-}"; shift 2 ;;
        --target) TARGETS+=("${2:-}"); shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ ! -f "$SUMMARY" ]; then
    echo "Claims validation failed: summary file missing ($SUMMARY)"
    exit 1
fi

total_runs=$(jq -r '.total_runs // 0' "$SUMMARY")
precision=$(jq -r '.precision // 0' "$SUMMARY")
recall=$(jq -r '.recall // 0' "$SUMMARY")

evidence_ok=1
if [ "$total_runs" -lt "$MIN_RUNS" ]; then
    evidence_ok=0
fi
if ! awk -v p="$precision" -v m="$MIN_PRECISION" 'BEGIN { exit !(p >= m) }'; then
    evidence_ok=0
fi
if ! awk -v r="$recall" -v m="$MIN_RECALL" 'BEGIN { exit !(r >= m) }'; then
    evidence_ok=0
fi

if [ "$evidence_ok" -eq 1 ]; then
    echo "Claims validation passed: evidence gate met."
    exit 0
fi

echo "Evidence gate not met (runs=$total_runs precision=$precision recall=$recall)."
echo "Checking for unsupported strong efficacy claims..."

# Patterns indicating strong efficacy/validation claims.
claim_pattern='state-of-the-art|SOTA|production-ready detection|guarantee|guaranteed|achieves [0-9]+%|precision[: ]+[0-9]|recall[: ]+[0-9]|outperform'

found=0
for target in "${TARGETS[@]}"; do
    if [ ! -f "$target" ]; then
        continue
    fi
    if grep -Ein "$claim_pattern" "$target" >/tmp/claims_hits.txt 2>/dev/null; then
        echo "Unsupported claim pattern found in $target:"
        cat /tmp/claims_hits.txt
        found=1
    fi
done
rm -f /tmp/claims_hits.txt

if [ "$found" -eq 1 ]; then
    exit 1
fi

echo "Claims validation passed: no unsupported strong efficacy claims found."
