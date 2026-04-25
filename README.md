# Agent Security -- Research Paper

**"Runtime Security for Agentic Systems: A Practical Two-Plane Approach for OpenClaw-Class Agents"**

Authors: Frank Lyonnet, Antoine Clerget, Kave Salamatian

This repository contains the whitepaper draft, figure generation pipeline, and
publication artifacts for the two-plane runtime security paper.

## Repository Structure

```
paper/
  whitepaper_draft.md     # Canonical paper source (Markdown)
  CHANGELOG.md            # Paper revision history
  generate_figures.py     # Figure generation from SVG sources
  svg-to-pdf.lua          # Pandoc Lua filter for SVG-to-PDF
  figures/                # SVG, PNG, and PDF figures
scripts/
  build_paper_bundle.sh   # Inject live metrics into draft, produce bundle
  regen_paper.sh          # Full regeneration (bundle + TeX + PDF)
  summarize_results.sh    # Recompute public summary from published NDJSON rows
  reproduce_results.sh    # Public artifact-level paper reproduction entrypoint
  preflight_publication.sh # Pre-publication consistency checks
  readiness_gate.sh       # Publication readiness gate
tests/
  e2e/
    triggers/             # 11 CVE/divergence trigger scripts + cleanup
    run_demo.sh           # Demo orchestrator (--focus vuln|divergence|all)
    run_e2e_harness.sh    # Automated E2E harness for CI
    DEMO.md               # Step-by-step demo reproduction guide
    E2E_TESTS.md          # E2E test architecture reference
  benchmark/
    live-scenarios/       # 50 versioned JSON scenario contracts
    run_live_suite.py     # Live benchmark harness (Lima VM orchestrator)
    run_live_suite.sh     # Wrapper script
    summarize_results.sh  # Metric computation from NDJSON traces
    record_result.sh      # Single-result NDJSON appender
    validate_claims.sh    # Paper-claim evidence bounds checker
    generate_cve_report.py # CVE-centric pass/fail report generator
  lib/
    vm_exec.sh            # Lima VM execution helpers
    mcp_bootstrap.sh      # MCP helper deployment and divergence wrappers
docs/
  CLAIM_ARTIFACT_INDEX.md # Claim-to-artifact mapping
  LLM_USAGE.md            # LLM usage disclosure
  manifest-schema.json    # Formal JSON Schema for run manifests
artifacts/
  live-paper-summary.json # Canonical benchmark summary
  live-paper-manifest.json # Canonical run manifest
  live-paper-results.ndjson # Canonical row-level live benchmark results
  paper-bundle/           # Generated outputs (md, tex, pdf)
  readiness-scorecard.*   # Publication readiness assessment
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
  paper/whitepaper_draft.md \
  artifacts/paper-bundle

# Step 2: Regenerate all formats
bash scripts/regen_paper.sh

# Step 3: Validate publication readiness
bash scripts/preflight_publication.sh
```

`python3 paper/generate_figures.py` now performs strict layout validation and
fails if a diagram has text overflow, clipped labels, or overlapping content
boxes.

The live benchmark summary and manifest JSON files are produced by the
benchmark harness in `tests/benchmark/run_live_suite.py`.

### Public artifact-level reproduction

To reproduce the paper outputs from the published row-level benchmark artifacts
already committed in this repository:

```bash
bash scripts/reproduce_results.sh
```

This recomputes `artifacts/live-paper-summary.json` from
`artifacts/live-paper-results.ndjson`, rebuilds the paper bundle/PDF, and reruns
the readiness and preflight checks.

For a fresh live rerun of the full benchmark (requires a configured Lima VM
with EDAMAME Posture):

```bash
python3 tests/benchmark/run_live_suite.py --mode live
```

The public paper repo does not carry private soundness or credibility notes.
If you want to embed a private supporting-evidence document while regenerating
locally, pass it via `PAPER_SUPPORTING_EVIDENCE=/path/to/private-note.md` or
use the five-argument form of `scripts/build_paper_bundle.sh`.

Rendered review pages land in `paper/pdf-pages/review/` and are gitignored.
The generated `review-index.json` also audits sequential figure numbering and
caption/page alignment plus rendered page-layout overflow; treat the review as
incomplete unless it reports both `numbering_ok: true` and
`page_layout_ok: true`.

Override the inputs with `PAPER_SUMMARY`, `PAPER_MANIFEST`, and
`PAPER_RESULTS` if you need to regenerate from a different run snapshot.

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
| `WHITEPAPER_GENERATED.build.log` | Raw Pandoc/Tectonic PDF build log |
| `appendix-metrics.md` | Metrics appendix |
| `reproducibility-report.md` | Reproducibility report |
| `bundle-index.json` | Bundle manifest |

## Quick Links

- [Canonical paper source](paper/whitepaper_draft.md)
- [Latest generated PDF](artifacts/paper-bundle/WHITEPAPER_GENERATED.pdf)
- [Canonical claim index](docs/CLAIM_ARTIFACT_INDEX.md)
- [Canonical benchmark summary](artifacts/live-paper-summary.json)
- [Demo guide -- vulnerability and divergence detection](tests/e2e/DEMO.md)
- [E2E test architecture](tests/e2e/E2E_TESTS.md)

## Related Repositories

| Repository | Purpose |
|------------|---------|
| [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) | OpenClaw agent integration package |
| [edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) | Cursor developer workstation package |
| [edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) | Claude Code developer workstation plugin |
| [edamame_security](https://github.com/edamametechnologies/edamame_security) | EDAMAME Security desktop/mobile app -- see [AGENTIC.md](https://github.com/edamametechnologies/edamame_security/blob/main/AGENTIC.md) for CVE detection, divergence, and E2E test details |
| [edamame_posture](https://github.com/edamametechnologies/edamame_posture) | EDAMAME Posture CLI for CI/CD and servers |
| [edamame_core_api](https://github.com/edamametechnologies/edamame_core_api) | EDAMAME Core public API documentation |
| [threatmodels](https://github.com/edamametechnologies/threatmodels) | Public security benchmarks and threat models |

See the full [EDAMAME Technologies](https://github.com/edamametechnologies) organization for all repositories.

### Agent Integration Installation

- **edamame_claude_code** (Claude Code): Easy install via Claude Code marketplace:
  ```shell
  /plugin marketplace add edamametechnologies/edamame_claude_code
  /plugin install edamame@edamame-security
  ```
- **edamame_cursor** (Cursor): See [edamame_cursor README](https://github.com/edamametechnologies/edamame_cursor) for Cursor Marketplace or manual install (pending marketplace publication).
- **edamame_openclaw** (OpenClaw): See [edamame_openclaw README](https://github.com/edamametechnologies/edamame_openclaw) for plugin bundle and Lima VM provisioning.
