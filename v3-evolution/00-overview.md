# v3 — Architecture Redesign

> Scope: this folder is the implementation plan for the v3 redesign of
> `sast-triage-agent`. Each numbered file is one self-contained unit of
> work that can be picked up and executed independently.
>
> Strategic background: `redesign-analysis.md` (repo root).
> Existing prior work: `v2-evolution/` (kept for reference).

## What v3 is

v3 turns the current single-pass ReAct agent into a structured
multi-LLM pipeline (researcher → analyst → critic with sample-voting
for calibrated confidence), driven by per-CWE prompt checklists and
finding-level clustering. The goals are:

1. **Reduce false negatives.** The current high-confidence-FN failure
   mode is the published failure mode of self-reported LLM confidence.
   A separate critic LLM + N-sample self-consistency replaces the
   theatrical `verify_analysis` self-check with externally-grounded
   agreement signal.
2. **Calibrate confidence.** Verdict confidence becomes a function of
   sample agreement rate and evidence count, not the model's
   self-report.
3. **Add a safety valve.** New `PROPOSED_NOT_EXPLOITABLE` verdict
   state routes uncertain dismissals to human review instead of
   silently dropping them.
4. **Scale to 2000 apps.** Finding clustering with representative
   analysis amortizes the per-finding cost across similar findings
   (typical 5-10× reduction at scale).
5. **Simplify what's there.** Rip out Phoenix tracing (high cost, low
   value); refactor toward small, focused modules.

## Top-line success criteria

Measured against the gold-set (see `02-gold-set-benchmark.md`),
before any v3 change ships:

- **CONFIRMED recall ≥ 0.90** (current: ~0.80-0.85 estimated, no
  gold-set yet to confirm)
- **NOT_EXPLOITABLE precision ≥ 0.92** (current: unknown)
- **Confidence calibration**: among findings reported as
  `assessment_confidence ≥ 0.9`, actual accuracy ≥ 0.9 ± 0.05
- **Verdict stability**: re-running the same finding 5 times yields
  the same verdict ≥ 95% of the time
- **Per-finding cost** with full critic+sampling under $0.60 average,
  with clustering bringing real-world workload cost to under $0.10
  per finding amortized

Direction (not gates) for v3.0 ship: all four ≥ targets met on the
gold-set, with at least 100 findings reviewed.

## Guiding principles

These should be applied throughout every implementation step:

1. **Externalize structure.** Gemini 2.5 Pro is a capable analyst
   that needs an externally-imposed process. Don't trust the model
   to self-regulate.
2. **Simple, clean, maintainable.** Prefer plain Python over
   framework abstractions. Don't add a layer of indirection for
   something used once. If a tool, util, or config option isn't
   actively used, delete it.
3. **Measure, don't speculate.** Every architectural change is gated
   on a gold-set benchmark improvement. No change ships without
   numbers.
4. **Evidence-based design.** When in doubt about a design choice,
   defer to the cited literature (see `redesign-analysis.md`) over
   intuition.
5. **Smallest viable scope.** Each implementation unit is ≤ 1 week
   of work. If it looks like more, split it.

## Reading order

For someone picking up this folder cold:

1. `00-overview.md` — this file
2. `01-architecture.md` — the target architecture diagrammed
3. `99-roadmap.md` — phased rollout, sequencing, dependencies
4. Individual implementation docs (02-11), in the order given by
   `99-roadmap.md`

## Reading order for implementers

When ready to start work, follow `99-roadmap.md` strictly. The phase
ordering is not arbitrary — early phases provide the measurement
infrastructure that later phases depend on for validation.

## Out of scope for v3

To keep v3 finite and shippable:

- **Replacement of Checkmarx as the source SAST tool.** v3 still
  consumes Checkmarx One findings.
- **Multi-tool aggregation** (e.g. Semgrep + Checkmarx fusion).
- **Auto-remediation / PR generation.** v3 is triage-only.
- **HITL review UI.** v3 produces a structured queue of
  `PROPOSED_NOT_EXPLOITABLE` findings; reviewing them is out of scope
  (handled by Checkmarx One's own UI or a spreadsheet export).
- **FAISS known-FP corpus.** Deferred until a feedback loop with
  analyst verdicts exists. See `redesign-analysis.md` §4.3.
- **Cross-file callers/callees in tree-sitter.** Function-at-line
  extraction is in scope (`08-tree-sitter-extraction.md`); call-graph
  navigation is a future enhancement.

## What stays unchanged from v2

- Checkmarx One API integration (`utils/checkmarx_helpers.py`)
- Repository cloning and preprocessing (`utils/`, secret masking,
  obfuscation)
- Path-traversal validation (`agent_tools.py:validate_safe_path`)
- The Click CLI layout (`run_triage.py`, `run_benchmark.py`)
- Per-finding logging and `--compact-logs` flag (recently added)
- The Pydantic verdict model — extended, not replaced
