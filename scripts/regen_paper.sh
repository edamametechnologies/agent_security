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
SOURCE_SOUNDNESS="$REPO_DIR/docs/SOUNDNESS_ANALYSIS_2026-02-18.md"
OPENCLAW_DIR="$REPO_DIR/../openclaw_security"
LIVE_SUMMARY="${PAPER_SUMMARY:-$OPENCLAW_DIR/artifacts/live-paper-summary.json}"
LIVE_MANIFEST="${PAPER_MANIFEST:-$OPENCLAW_DIR/artifacts/live-paper-manifest.json}"
LIVE_SUMMARY_ALT="$OPENCLAW_DIR/artifacts/live-paper-new-summary.json"
LIVE_MANIFEST_ALT="$OPENCLAW_DIR/artifacts/live-paper-new-manifest.json"

if [ ! -f "$LIVE_SUMMARY" ] && [ -f "$LIVE_SUMMARY_ALT" ]; then
    LIVE_SUMMARY="$LIVE_SUMMARY_ALT"
fi
if [ ! -f "$LIVE_MANIFEST" ] && [ -f "$LIVE_MANIFEST_ALT" ]; then
    LIVE_MANIFEST="$LIVE_MANIFEST_ALT"
fi

RUN_DEMO=false
for arg in "$@"; do
    case "$arg" in
        --demo) RUN_DEMO=true ;;
    esac
done

if [ -f "$SOURCE_DRAFT" ] && [ -f "$LIVE_SUMMARY" ] && [ -f "$LIVE_MANIFEST" ]; then
    echo "Refreshing paper bundle markdown from $SOURCE_DRAFT..."
    "$SCRIPT_DIR/build_paper_bundle.sh" \
        "$LIVE_SUMMARY" \
        "$LIVE_MANIFEST" \
        "$SOURCE_DRAFT" \
        "$SOURCE_SOUNDNESS" \
        "$BUNDLE_DIR"
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

echo "Generating TeX..."
pandoc "WHITEPAPER_GENERATED.md" -o "WHITEPAPER_GENERATED.tex" --standalone \
    --lua-filter="$PAPER_DIR/$SVG_FILTER" \
    --resource-path="$PAPER_DIR"
echo "  -> WHITEPAPER_GENERATED.tex ($(wc -c < "WHITEPAPER_GENERATED.tex" | tr -d ' ') bytes)"

echo "Generating PDF (vector SVG via tectonic)..."
pandoc "WHITEPAPER_GENERATED.md" -o "WHITEPAPER_GENERATED.pdf" \
    --pdf-engine=tectonic \
    --lua-filter="$PAPER_DIR/$SVG_FILTER" \
    --resource-path="$PAPER_DIR" 2>&1 \
    | grep -v "^warning:" || true
echo "  -> WHITEPAPER_GENERATED.pdf ($(wc -c < "WHITEPAPER_GENERATED.pdf" | tr -d ' ') bytes)"

popd >/dev/null

echo ""
echo "Whitepaper formats regenerated from WHITEPAPER_GENERATED.md."

if [ "$RUN_DEMO" = true ]; then
    echo ""
    echo "Demo video recording is handled by openclaw_security:"
    echo "  cd ../openclaw_security && ./scripts/capture_demo_terminal_mp4.sh"
fi

echo ""
echo "Done."
