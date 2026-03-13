# External Review Response (2026-02-24)

This note records how comments from the deep research report and reviewer
feedback are incorporated across repo, paper, and demo artifacts.

## Scope of Received Comments

1. Repo/paper comments from `deep-research-report (5).md` apply to:
   - claim-to-artifact consistency,
   - reproducibility governance,
   - CI realism boundaries,
   - LLM disclosure/process hardening.
2. Paper comment on Appendix B:
   - distinguish LangGraph framework/library from LangGraph managed service,
   - clarify that skills and frameworks are complementary,
   - clarify that OpenClaw cron can act as lightweight orchestration.
3. Deck comment:
   - rendering quality is poor (picture layout and text density in PDF/PPTX).

## Paper Changes Applied

- Updated `paper/arxiv_draft.md` Appendix B (`B.1`, `B.3`, `B.4`, `B.5`) to:
  - separate framework/library layer vs service/observability layer,
  - state explicitly that skills/manifests and frameworks are not exclusive,
  - mention OpenClaw cron scheduling as orchestration behavior,
  - simplify and shorten the portability wording.
- Updated `paper/arxiv_draft.md` evaluation sections to remove mixed historical
  metric snapshots and bind narrative claims to the canonical live artifact
  family (`live-paper-summary`, `live-paper-manifest`, `live-paper-results`).
- Updated `paper/generate_figures.py` Figure 5 to consume canonical live summary
  data directly and align figure output with claim-bearing artifacts.

## Deck Changes Applied

- Updated `demo/scripts/build_exec_demo_pptx.py`:
  - improved visual layout policy for image slides (aspect-ratio preserving),
  - simplified wording and slide titles for readability,
  - added explicit slide: framework/library vs service vs skill,
  - increased readability (spacing/line-height) and reduced video/footer overlap.
- Updated `demo/scripts/generate_exec_demo_graphics.py`:
  - switched to light, presentation-friendly color palette,
  - reduced text density in boxes,
  - simplified scenario/CVE matrix rendering for readability,
  - raised export DPI for cleaner PDF output.
- Added deterministic companion document generation:
  - `demo/scripts/build_exec_demo_docx.py`,
  - `demo/OpenClaw-Exec-Demo-Architecture-2026-Companion.docx`.

## Repo-Wide Follow-up Alignment

The deep research report recommendations remain tracked in:

- `GAPS.md` for prioritized remediation (H4/H5/M5 and residual tests),
- `docs/CLAIM_ARTIFACT_INDEX.md` for strict metric binding,
- `docs/TESTING.md` for benchmark/readiness protocol.

Additional high-priority follow-ups from the external review:

1. Refresh canonical claim bindings to a run with explicit `benchmark_mode`
   (remove historical `unknown` ambiguity).
2. Add dedicated disclosure/governance doc for LLM-dependent paths. ✅
   - Implemented in `docs/LLM_USAGE.md`.
3. Decide and codify whether `real_lima` is release-gating or best-effort. ⏳
   - Current policy is explicitly documented as split trust-boundary
     (hosted integration + scheduled self-hosted real-Lima).

## Status

- Appendix B readability/clarity comment: addressed.
- Framework vs service distinction: addressed.
- Skills + framework complementarity statement: addressed.
- Deck rendering readability pass: addressed through deterministic rebuild loop
  and PDF export validation.
- LLM governance disclosure document: addressed (`docs/LLM_USAGE.md`).
- Canonical claim consistency cleanup: in progress (final binding depends on
  fresh strict-mode benchmark artifact regeneration).
