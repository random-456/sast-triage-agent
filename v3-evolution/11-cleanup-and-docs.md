# 11 — Cleanup, documentation refresh, archival

> Scope: the final pass. Make the docs reflect what actually
> shipped; remove dead code; verify the README is accurate for a new
> contributor.
>
> Depends on: every other v3 phase shipped.
> Last phase before v3.0 cut.

## Goal

A new contributor can `git clone`, read the docs, and understand
the system without reading source code. No stale references to
removed features.

## Documentation principles (apply to every shipped doc)

These govern all documentation that ships in the product (`docs/`,
`README.md` and anything else on feature/dev branches):

- **Neutral, present-tense.** Describe what the system *is* and how
  it works, with the rationale behind each design decision. Do
  **not** write it as a changelog or migration narrative (no "we
  changed X", no version-to-version framing). A reader should see a
  coherent description of the current system, not its history.
- **Comprehensive with justifications.** Cover the important design
  topics and *why* each choice was made (e.g. why a separate critic,
  why agreement-based confidence, why dataflow-guided retrieval).
  The reasoning is part of the documentation, not just the
  mechanics.
- **No unproven quantitative claims.** Either cite a source, or
  phrase qualitatively ("can be expected to", "tends to"). Never
  state a specific improvement/saving multiplier as fact without
  evidence.
- **No specific organizational scale figures.** Describe scale
  qualitatively ("large application portfolios", "high-volume
  projects"), never with concrete app/repo/finding counts.
- **No references to outside parties or private discussions**, and
  **no reference to any external comparator project.** These inform
  our reasoning but must not appear in shipped docs.

**Planning material is not shipped.** `redesign-analysis.md` and the
`v3-evolution/` folder are working/scratch documents and are **not
committed to feature/dev branches**. Only the cleaned, final
documentation in `docs/` and `README.md` ships. The planning folders
may contain framing and references that the shipped docs must not.

## Documentation refresh

### `README.md`

Update sections:
- **Quick Start** — keep, but update env var examples
  (`GOOGLE_GENAI_USE_VERTEXAI`, etc. per `03-llm-backend.md`).
- **Usage** — add new flags from v3 (`--no-clustering`,
  `--samples N`, etc.); remove `--trace`.
- **Key Options** — table refreshed; drop Phoenix row, add
  clustering controls.
- **Output:** document the output schema from `06-output-model.md`
  (`is_vulnerable`, `confidence`, `suggested_state`, `justification`,
  `agreement_rate`, `sample_count`) plus the clustering fields
  `clustered_with` and `cluster_size`.
- **Documentation** — link to new docs.

### `docs/architecture.md`

Rewrite the architecture description. The Mermaid diagram from
`v3-evolution/01-architecture.md` becomes the new canonical diagram,
superseding the previous one.

Sections:
1. High-level pipeline (fetch → cluster → per-finding → aggregate to
   local output).
2. Per-finding subgraph (researcher → analyst → critic +
   self-consistency).
3. Key components table (each component file path + responsibility).
4. State flow.
5. Determinism + calibration stance.

### `docs/usage-guide.md`

- Drop Phoenix section.
- Update options table for v3.
- Add a "Verdict states" subsection covering the new
  `PROPOSED_NOT_EXPLOITABLE`.
- Add a "Confidence interpretation" subsection: what 0.9 means,
  how it's computed (agreement-based, not self-reported).

### `docs/benchmark.md`

- Update KPI fields to include `escalation_rate`,
  `near_miss_save_rate`, `verdict_stability_rate`,
  `calibration_table`.
- Update threshold table for v3-specific gates.
- Add a "Gold-set composition" subsection describing the dataset
  shape, TP/FP balance, per-CWE coverage.

### `docs/configuration.md`

- Update env vars: drop `PROJECT_ID`, `DEFAULT_LOCATION` (Vertex-
  specific naming); add `GOOGLE_GENAI_USE_VERTEXAI`,
  `GOOGLE_CLOUD_PROJECT`, `GOOGLE_API_KEY`.
- Drop Phoenix env vars.
- Add new configurable knobs:
  - `DEFAULT_SAMPLES`
  - `ANALYST_TEMPERATURES`
  - `CRITIC_TEMPERATURE`
  - `CONFIDENCE_THRESHOLD`
  - `AGREEMENT_THRESHOLD`
  - `MAX_RESEARCH_ITERATIONS`
  - `MAX_REANALYSIS_LOOPS`

### New docs

- `docs/confidence.md` — explains the agreement-rate confidence
  model. References the self-consistency aggregator. Explains
  why self-reported confidence is logged but not used as the
  primary signal.
- `docs/checklists.md` — explains the per-CWE checklist system.
  Lists currently-supported CWEs; documents how to add a new
  checklist.
- `docs/clustering.md` — explains the clustering signature and
  representative-selection logic. Documents how to disable
  clustering and when you'd want to.

## Code cleanup

### Removals

- `sast_triage/tracing.py` (already removed in Phase 1 per
  `10-phoenix-removal.md`; verify still gone).
- `tests/test_tracing.py` (ditto).
- `sast_triage/agent_tools.py:verify_analysis` (replaced by
  critic; remove the function and any remaining test stubs).
- Any `--trace` references in `run_triage.py` (verify).
- Any orphaned helper functions left over from the previous manual
  ReAct loop.

### Renames / reorganization

If the v3 implementation has grown into:

```
sast_triage/
├── graph/                  # new: LangGraph nodes and routing
│   ├── state.py
│   ├── nodes.py
│   ├── routing.py
│   └── build.py
├── checklists/             # new: YAML checklist content
│   ├── _mapping.yaml
│   ├── _schema.yaml
│   ├── sqli.yaml
│   └── ...
├── clustering/             # new: signature-based clustering
│   └── __init__.py
├── tools/                  # new: tool definitions split out
│   ├── extract_function.py
│   ├── read_file.py
│   └── search_in_files.py
├── prompts.py              # researcher / analyst / critic prompts
├── agent_models.py         # Pydantic schemas
├── agent_logging.py        # unchanged, includes compact-logs
├── aggregator.py           # new: self-consistency
└── agent.py                # now slim: just orchestrates graph
```

Consolidate. Move dispersed helpers into one of the modules above.

### Lint pass

Run the project's existing linter (whatever's configured —
ruff, flake8, etc.) and fix violations. Add a CI hook if not
already present.

## Archival

### `redesign-analysis.md`

Add a short prefatory note at the top:

> Analysis document from May 2026 that motivated the v3
> redesign. Implementation plans are in `v3-evolution/`. This
> document is preserved as the strategic rationale and may not
> reflect every detail of the shipped implementation.

### `sast-ai-workflow/`

The cloned comparator project. Either:
- **Drop entirely** (we've extracted what we need).
- Or keep as `sast-ai-workflow/` with the existing
  `sast-ai-workflow-analysis.md` summary, for posterity.

Recommendation: drop. It's ~ thousands of files we don't use.

## Acceptance criteria

- A new contributor can clone, follow `README.md`, and run a
  benchmark without reading any v3-evolution doc.
- No file in the repo references `phoenix`, `arize`,
  `openinference`, `--trace`, `verify_analysis`, `ChatVertexAI`,
  `PROJECT_ID` (Vertex-specific naming), or `sast-ai-workflow`
  (the cloned comparator) except in archived/historical
  documents.
- `docs/architecture.md` reflects the actual codebase, not the
  planning docs.
- `git log` for the cleanup phase is small and focused — no
  bundled functional changes.

## Risks / rollback

- **Risk:** doc rewrite ships before a feature it describes is
  fully working. **Mitigation:** Phase 5 runs *after* every
  other phase has shipped and benchmarked. If something isn't
  shipped, don't document it as shipped.
- **Rollback:** docs and structural moves are easy to revert; the
  only risk is reverting too aggressively and re-introducing
  stale content. Single-commit revert is fine.

## Out of scope

- A new user-facing brand / rename of the tool. Out of scope for
  a redesign.
- Migrating tests to pytest-bdd / behaviour-driven format.
  Useful in principle, not Phase 5 work.
- Setting up GitHub Actions / CI from scratch. Useful but
  separate from the redesign.
