#!/bin/bash
# regen_paper.sh — Regenerate whitepaper PDF and TeX, and optionally demo video
#
# Source: artifacts/paper-bundle/WHITEPAPER_GENERATED.md (produced by build_paper_bundle.sh)
# Output: artifacts/paper-bundle/WHITEPAPER_GENERATED.{tex,pdf}
#
# Prerequisites: pandoc, tectonic (brew install pandoc tectonic)
# Demo video:    asciinema, agg, ffmpeg (brew install asciinema agg ffmpeg)
#
# Usage:
#   ./scripts/regen_paper.sh            # paper formats only
#   ./scripts/regen_paper.sh --demo     # paper formats + demo video
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PAPER_DIR="$REPO_DIR/paper"
BUNDLE_DIR="$REPO_DIR/artifacts/paper-bundle"
SRC="$BUNDLE_DIR/WHITEPAPER_GENERATED.md"
FIG_GEN="$PAPER_DIR/generate_figures.py"
SOURCE_DRAFT="$PAPER_DIR/arxiv_draft.md"
SOURCE_SUPPORTING_EVIDENCE="${PAPER_SUPPORTING_EVIDENCE:-}"
LOCAL_SUMMARY="$REPO_DIR/artifacts/live-paper-summary.json"
LOCAL_MANIFEST="$REPO_DIR/artifacts/live-paper-manifest.json"
LOCAL_RESULTS="$REPO_DIR/artifacts/live-paper-results.ndjson"

RUN_DEMO=false
for arg in "$@"; do
    case "$arg" in
        --demo) RUN_DEMO=true ;;
    esac
done

sync_canonical_artifact() {
    local source="$1"
    local dest="$2"
    local label="$3"

    if [ ! -f "$source" ]; then
        return
    fi

    mkdir -p "$(dirname "$dest")"
    if [ "$source" = "$dest" ]; then
        echo "  -> $label ($(basename "$dest"), already canonical)"
        return
    fi

    if [ -f "$dest" ] && cmp -s "$source" "$dest"; then
        echo "  -> $label ($(basename "$dest"), unchanged)"
        return
    fi

    cp "$source" "$dest"
    echo "  -> $label ($(basename "$dest"))"
}

choose_latest_manifest() {
    python3 - "$@" <<'PY'
import json
import os
import re
import sys

best_path = None
best_key = None
for path in sys.argv[1:]:
    if not path or not os.path.isfile(path):
        continue
    run_id = ""
    try:
        with open(path, encoding="utf-8") as handle:
            run_id = str(json.load(handle).get("run_id", ""))
    except Exception:
        pass
    match = re.search(r"run-live-(\d{8}T\d{6}Z)-", run_id)
    if match:
        key = (2, match.group(1), os.path.getmtime(path))
    else:
        key = (1, "", os.path.getmtime(path))
    if best_key is None or key > best_key:
        best_key = key
        best_path = path
if best_path:
    print(best_path)
PY
}

choose_latest_file() {
    python3 - "$@" <<'PY'
import os
import sys

best_path = None
best_mtime = None
for path in sys.argv[1:]:
    if not path or not os.path.isfile(path):
        continue
    mtime = os.path.getmtime(path)
    if best_mtime is None or mtime > best_mtime:
        best_mtime = mtime
        best_path = path
if best_path:
    print(best_path)
PY
}

shopt -s nullglob
MANIFEST_CANDIDATES=("$LOCAL_MANIFEST")
SUMMARY_CANDIDATES=("$LOCAL_SUMMARY")
RESULTS_CANDIDATES=("$LOCAL_RESULTS")
shopt -u nullglob

SOURCE_MANIFEST="${PAPER_MANIFEST:-}"
if [ -z "$SOURCE_MANIFEST" ]; then
    SOURCE_MANIFEST="$(choose_latest_manifest "${MANIFEST_CANDIDATES[@]}")"
fi

MANIFEST_PREFIX=""
if [ -n "$SOURCE_MANIFEST" ] && [[ "$SOURCE_MANIFEST" == *-manifest.json ]]; then
    MANIFEST_PREFIX="${SOURCE_MANIFEST%-manifest.json}"
fi

SOURCE_SUMMARY="${PAPER_SUMMARY:-}"
if [ -z "$SOURCE_SUMMARY" ] && [ -n "$MANIFEST_PREFIX" ] && [ -f "${MANIFEST_PREFIX}-summary.json" ]; then
    SOURCE_SUMMARY="${MANIFEST_PREFIX}-summary.json"
fi
if [ -z "$SOURCE_SUMMARY" ]; then
    SOURCE_SUMMARY="$(choose_latest_file "${SUMMARY_CANDIDATES[@]}")"
fi

SOURCE_RESULTS="${PAPER_RESULTS:-}"
if [ -z "$SOURCE_RESULTS" ] && [ -n "$MANIFEST_PREFIX" ] && [ -f "${MANIFEST_PREFIX}-results.ndjson" ]; then
    SOURCE_RESULTS="${MANIFEST_PREFIX}-results.ndjson"
fi
if [ -z "$SOURCE_RESULTS" ]; then
    SOURCE_RESULTS="$(choose_latest_file "${RESULTS_CANDIDATES[@]}")"
fi

echo "Syncing canonical live artifacts into agent_security..."
sync_canonical_artifact "$SOURCE_SUMMARY" "$LOCAL_SUMMARY" "summary"
sync_canonical_artifact "$SOURCE_MANIFEST" "$LOCAL_MANIFEST" "manifest"
sync_canonical_artifact "$SOURCE_RESULTS" "$LOCAL_RESULTS" "results"
echo ""

LIVE_SUMMARY="$LOCAL_SUMMARY"
LIVE_MANIFEST="$LOCAL_MANIFEST"
if [ ! -f "$LIVE_SUMMARY" ]; then
    LIVE_SUMMARY="$SOURCE_SUMMARY"
fi
if [ ! -f "$LIVE_MANIFEST" ]; then
    LIVE_MANIFEST="$SOURCE_MANIFEST"
fi

if [ -f "$SOURCE_DRAFT" ] && [ -f "$LIVE_SUMMARY" ] && [ -f "$LIVE_MANIFEST" ]; then
    echo "Refreshing paper bundle markdown from $SOURCE_DRAFT..."
    if [ -n "$SOURCE_SUPPORTING_EVIDENCE" ]; then
        "$SCRIPT_DIR/build_paper_bundle.sh" \
            "$LIVE_SUMMARY" \
            "$LIVE_MANIFEST" \
            "$SOURCE_DRAFT" \
            "$SOURCE_SUPPORTING_EVIDENCE" \
            "$BUNDLE_DIR"
    else
        "$SCRIPT_DIR/build_paper_bundle.sh" \
            "$LIVE_SUMMARY" \
            "$LIVE_MANIFEST" \
            "$SOURCE_DRAFT" \
            "$BUNDLE_DIR"
    fi
    echo ""
fi

if [ ! -f "$SRC" ]; then
    echo "Error: $SRC not found"
    echo "Run scripts/build_paper_bundle.sh first to generate WHITEPAPER_GENERATED.md"
    exit 1
fi

for cmd in pandoc tectonic rsvg-convert; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found. Install via: brew install pandoc tectonic librsvg"
        exit 1
    fi
done

echo "Source: $SRC"
echo ""

# Keep figure artifacts in sync with paper source before export.
if [ -f "$FIG_GEN" ]; then
    echo "Generating figures..."
    python3 "$FIG_GEN"
    echo ""
fi

pushd "$PAPER_DIR" >/dev/null

# Convert SVG figures to PDF vector graphics for LaTeX embedding.
echo "Converting SVGs to PDF vector figures..."
for svg in figures/*.svg; do
    [ -f "$svg" ] || continue
    pdf="${svg%.svg}.pdf"
    rsvg-convert -f pdf -o "$pdf" "$svg"
done
echo "  -> $(ls figures/*.pdf 2>/dev/null | wc -l | tr -d ' ') PDF figures generated"

SVG_FILTER="svg-to-pdf.lua"

popd >/dev/null

pushd "$BUNDLE_DIR" >/dev/null

BUILD_LOG="WHITEPAPER_GENERATED.build.log"

echo "Generating TeX..."
pandoc "WHITEPAPER_GENERATED.md" -o "WHITEPAPER_GENERATED.tex" --standalone \
    --lua-filter="$PAPER_DIR/$SVG_FILTER" \
    --resource-path="$PAPER_DIR"
echo "  -> WHITEPAPER_GENERATED.tex ($(wc -c < "WHITEPAPER_GENERATED.tex" | tr -d ' ') bytes)"

echo "Generating PDF (vector SVG via tectonic)..."
pandoc "WHITEPAPER_GENERATED.md" -o "WHITEPAPER_GENERATED.pdf" \
    --pdf-engine=tectonic \
    --lua-filter="$PAPER_DIR/$SVG_FILTER" \
    --resource-path="$PAPER_DIR" 2>&1 | tee "$BUILD_LOG"
python3 - "$BUILD_LOG" <<'PY'
import sys

log_path = sys.argv[1]
text = open(log_path, encoding="utf-8", errors="replace").read()
issues = [
    needle
    for needle in (
        "Overfull \\hbox",
        "Overfull \\vbox",
        "Float too large for page",
    )
    if needle in text
]
if issues:
    raise SystemExit(
        "PDF layout warnings detected in build log: " + ", ".join(issues)
    )
PY
echo "  -> WHITEPAPER_GENERATED.pdf ($(wc -c < "WHITEPAPER_GENERATED.pdf" | tr -d ' ') bytes)"
echo "  -> $BUILD_LOG ($(wc -c < "$BUILD_LOG" | tr -d ' ') bytes)"

popd >/dev/null

echo ""
echo "Whitepaper formats regenerated from WHITEPAPER_GENERATED.md."

if [ "$RUN_DEMO" = true ]; then
    echo ""
    echo "Demo video recording requires a configured Lima VM environment."
fi

echo ""
echo "Done."
