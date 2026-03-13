# Agent Security -- Research Paper

**"Runtime Security for Agentic Systems: A Practical Two-Plane Approach for OpenClaw-Class Agents"**

Authors: Frank Lyonnet, Antoine Clerget

This repository contains the arXiv draft, figure generation pipeline, and
publication artifacts for the two-plane runtime security paper.

## Repository Structure

```
paper/
  arxiv_draft.md          # Canonical paper source (Markdown)
  CHANGELOG.md            # Paper revision history
  generate_figures.py     # Figure generation from SVG sources
  svg-to-pdf.lua          # Pandoc Lua filter for SVG-to-PDF
  figures/                # SVG, PNG, and PDF figures
scripts/
  build_paper_bundle.sh   # Inject live metrics into draft, produce bundle
  regen_paper.sh          # Full regeneration (bundle + TeX + PDF)
  preflight_publication.sh # Pre-publication consistency checks
  arxiv_readiness_gate.sh # arXiv submission readiness gate
docs/
  CLAIM_ARTIFACT_INDEX.md # Claim-to-artifact mapping
  CREDIBILITY_EVIDENCE.md # Evidence tracking per claim
  SOUNDNESS_ANALYSIS_*.md # Soundness analysis
  LLM_USAGE.md            # LLM usage disclosure
  REVIEW_RESPONSE_*.md    # Reviewer response
artifacts/
  paper-bundle/           # Generated outputs (md, tex, pdf)
  arxiv-readiness-scorecard.* # Readiness assessment
```

## Prerequisites

- [Pandoc](https://pandoc.org/) (Markdown to LaTeX/PDF)
- [Tectonic](https://tectonic-typesetting.github.io/) (TeX to PDF)
- `rsvg-convert` (SVG to PDF for figures)
- Python 3 (for figure generation)

## Regenerating the Paper

### Full pipeline (metrics + figures + TeX + PDF)

```bash
# Step 1: Build paper bundle (injects live metrics from benchmark results)
bash scripts/build_paper_bundle.sh \
  <summary.json> <manifest.json> \
  paper/arxiv_draft.md \
  docs/SOUNDNESS_ANALYSIS_2026-02-18.md \
  artifacts/paper-bundle

# Step 2: Regenerate all formats
bash scripts/regen_paper.sh

# Step 3: Validate publication readiness
bash scripts/preflight_publication.sh
```

The live benchmark summary and manifest JSON files are produced by the
benchmark harness in the [openclaw_security](https://github.com/edamametechnologies/openclaw_security)
repository (`./reproduce_live.sh`).

### Figures only

```bash
python3 paper/generate_figures.py
```

## Generated Outputs

After regeneration, `artifacts/paper-bundle/` contains:

| File | Description |
|------|-------------|
| `WHITEPAPER_GENERATED.md` | Paper with live metrics injected |
| `WHITEPAPER_GENERATED.tex` | LaTeX source |
| `WHITEPAPER_GENERATED.pdf` | Final PDF |
| `appendix-metrics.md` | Metrics appendix |
| `reproducibility-report.md` | Reproducibility report |
| `bundle-index.json` | Bundle manifest |

## Related Repositories

| Repository | Purpose |
|------------|---------|
| [openclaw_security](https://github.com/edamametechnologies/openclaw_security) | Dev/test/demo/CI monorepo (benchmark harness, live traces) |
| [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) | OpenClaw agent integration package |
| [edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) | Cursor developer workstation package |
