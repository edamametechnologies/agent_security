# Paper Changelog

## 2026-03-31

#### New content

- Added Section 7.10 (Observer Resource Footprint): CPU and memory measurements of `edamame-posture` 1.1.4 on the benchmark Lima VM (4 vCPU / 4 GiB, Ubuntu 24.04, aarch64). Three phases (idle/active/load) measured with `pidstat`. Bare-metal CPU estimates extrapolated from VZ hypervisor overhead. EDR comparison context included.
- New artifact: `artifacts/footprint-summary.json`.
- New script: `scripts/measure_footprint.sh`.

#### Editorial changes

- Authors changed from `Frank Lyonnet, Antoine Clerget` to `Frank Lyonnet, Antoine Clerget, Kave Salamatian`.
- Section 12 (Author Disclosure) updated to describe Kave Salamatian's affiliation (Université Savoie Mont Blanc, France) and confirm no competing interest with EDAMAME Technologies.
- Introduction: added paragraph previewing the three-loop system-plane decomposition, framing loops 2 and 3 as traditional EDR-style capabilities.
- Section 3: reinforced EDR framing for vulnerability/safety-floor and advisor/remediation loops.

## 2026-03-12

### Compared with the last committed paper (`HEAD`)

#### Scope and framing

- The paper moved from an `OpenClaw + EDAMAME` framing to a clearer `EDAMAME observer with multiple reasoning-plane producers` framing.
- The draft now explicitly states that EDAMAME can ingest agent-tagged behavioral-model slices from both OpenClaw and Cursor, merge them into one observer-owned correlation window, and preserve contributor attribution.
- The wording was normalized from `cortex/reptilian brain` style language to `reasoning plane/system plane`.
- The draft now distinguishes architectural claims from benchmark scope more carefully.

#### Headline measurement update

| Metric | Last committed paper | Current draft |
|---|---|---|
| Precision | `0.95` (CI95 `[0.835, 0.986]`) | `0.862` (CI95 `[0.815, 0.899]`) |
| Recall | `0.90` (CI95 `[0.779, 0.962]`) | `0.987` (CI95 `[0.962, 0.996]`) |
| Median latency | `42.3 s` | `45.8 s` |
| p95 latency | not reported | `53.6 s` |
| Evaluation framing | `50 scenarios, 8 categories` | `50 planned scenarios`, `273 valid runs`, `12 seeds`, plus integration-validated categories |

#### Confusion-matrix change

- Last committed paper: `TP 38 / FN 4 / FP 2 / TN 6`
- Current draft: `TP 225 / FN 3 / FP 36 / TN 9`

#### Interpretation change

- The newer draft makes the trade-off more explicit: recall improved materially, while precision dropped because the canonical live lineage now exposes a much larger benign-noise burden.
- False negatives and false positives are now analyzed by concentration bucket instead of mostly being discussed as designed misses.
- The current draft explicitly notes that the committed evidence lineage remains `NO_GO` for publication readiness because the precision CI95 lower bound is `0.815` and the skipped-run ratio is `38.7%`.

#### Architecture and claims

- The paper now explicitly documents both producer paths:
  - explicit-slice ingest via `upsert_behavioral_model`
  - raw-session ingest via `upsert_behavioral_model_from_raw_sessions`
- The limitation statement was corrected from `single-agent, single-host focus` to `single-observer, non-federated focus`.
- The draft now states that multi-agent contribution on a single observer-hosted engine is already implemented, while federated multi-host correlation is still not implemented.
- A benchmark-scope note was added to clarify that the aggregate metrics quantify EDAMAME's downstream divergence/correlation performance under the explicit-slice producer mode and do not directly measure transcript-to-model quality for either OpenClaw or Cursor.

#### Claim binding and canonical lineage

The paper is now bound to the newer canonical evidence lineage:

- `run_id`: `run-live-20260304T234441Z-live`
- `git_sha`: `473465c`
- `scenario_set_version`: `22cb4a6cbddf88154435207c279143f7245de94dbc47c5803ca349eb10f3de1d`

This replaces the older committed lineage and aligns the draft with:

- `docs/CLAIM_ARTIFACT_INDEX.md`
- `artifacts/live-paper-manifest.json`
- `artifacts/live-paper-summary.json`

#### Figures and generated outputs

- `fig1` through `fig7` were regenerated.
- The current draft also introduces:
  - `fig8_cron_sequence`
  - `fig9_divergence_engine`
- `fig5_results` now reflects the current canonical live evidence lineage rather than the older benchmark snapshot.
- Generated paper artifacts now include:
  - `artifacts/paper-bundle/WHITEPAPER_GENERATED.md`
  - `artifacts/paper-bundle/WHITEPAPER_GENERATED.pdf`

#### Editorial and structural changes

- Authors changed from `Frank Lyonnet, Antoine Clerget, Mark Day` to `Frank Lyonnet, Antoine Clerget`.
- Version changed from `2026-02-26` to `2026-03-02`.
- Section 7 was expanded substantially with stronger protocol details, per-category tables, readiness notes, and validation-scope language.
- A dedicated conclusion section was added.
- Terminology and limitations language were tightened to better match the current `edamame_core` implementation and current artifacts.
