# 99 — Phased rollout & sequencing

> Scope: the order in which the v3-evolution implementation docs
> should be executed, with dependencies, effort estimates, and
> per-phase ship gates.
>
> Depends on: every other v3-evolution doc.

## Implementation status (2026-05-27)

Phase 1 (foundations) and Phase 2 (LangGraph subgraph plus critic
and self-consistency) are merged into `dev`. The per-finding flow
runs end-to-end against mocked LLMs and the test suite (298 tests)
is green. A first live-LLM smoke test on real Gemini is the
immediate next activity before Phase 3 begins.

| Phase | Doc(s) | Status | Landed in |
|---|---|---|---|
| 0 | 02 (gold-set benchmark) | Deferred (user-owned) | n/a |
| 1 | 03, 04, 06, 10 | Done (2026-05-22) | PR #52 to #58 |
| 2 | 05, 07 | Done (2026-05-22) | PR #59 to #64 |
| 3 | 08 (code retrieval) | Not started | n/a |
| 4 | 09 (clustering) | Not started | n/a |
| 5 | 11 (cleanup and docs) | Not started | n/a |

Because Phase 0 is deferred, the per-phase ship gates that depend
on gold-set numbers (Phase 1 F1 movement, Phase 2 high-confidence
false-negative sweep, Phase 3 recall non-regression, Phase 4
cluster-propagation agreement) have not been evaluated. They remain
merge criteria once a gold-set exists; they are not closed.

For deviations from the originally planned slicing and ordering see
"Deviations from the original plan" below. The authoritative source
of merge status is `git log origin/dev`; this file is a planning
artifact and lags the code.

## Phase ordering rationale

Phase order is **not arbitrary**. It follows three rules:

1. **Measurement before mutation.** No architecture change ships
   without a gold-set to measure against. Phase 0 (gold-set) blocks
   everything else.
2. **Cheap structural wins first.** Prompt-level changes give the
   largest leverage per day of work. Architectural rewrites
   (LangGraph, clustering) come later because their benefit only
   materializes once the prompt and critic loop are in place.
3. **Independent units shipped independently.** Each phase produces
   a measurable change in the gold-set numbers. If a phase doesn't
   improve numbers, that's information — don't paper over it by
   bundling phases.

## Phase 0 — Measurement infrastructure (Week 0)

**Blocks:** everything.

**Status:** Deferred. Gold-set construction is user-owned and has
not been scheduled. Phases 1 and 2 shipped without baseline numbers;
the ship gates below that depend on gold-set numbers remain pending,
not closed.

| # | Doc | Effort |
|---|---|---|
| 1 | `02-gold-set-benchmark.md` | 3-5 days |

**Ship gate (pending):** gold-set committed; the current code
benchmarked against it; baseline numbers recorded. Even if the
baseline numbers are uncomfortable, write them down: they are the
floor.

## Phase 1 — Cheap structural wins (Week 1-2)

**Blocks Phase 2.** Independent of each other; can be parallelized
across implementers if needed.

**Status:** Done (2026-05-22). Implementation PRs, in merge order:

- #52: `10-phoenix-removal` (Phoenix tracing removed; `--trace` flag
  and optional deps gone).
- #53: `03-llm-backend` (unified `langchain-google-genai` client
  with Vertex AI and AI Studio backends resolved by
  `config.resolve_genai_backend`).
- #54: `06-output-model` (classification and disposition split;
  `is_vulnerable`, `confidence`, `suggested_state` derived via
  `derive_state`; read-only constraint codified).
- #55, #56: `04-prompt-redesign` part 1 (benchmark measures
  classification and disposition separately; mandatory five-step
  analysis protocol in the prompt).
- #57, #58: `04-prompt-redesign` part 2 (CWE checklist pipeline
  with SQLi exemplar, then top-5 content: XSS, command injection
  and path traversal).

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `03-llm-backend.md` | 1 day | langchain-google-genai migration; unblocks AI Studio dev |
| 2 | `04-prompt-redesign.md` (checklists + steps) | 5-7 days | Full CWE checklist set (subagent-authored) + mandatory analysis steps |
| 3 | `06-output-model.md` | 2 days | Two-field output (classification + disposition); read-only |
| 4 | `10-phoenix-removal.md` | 0.5 day | Clean-up |

**Ship gate (pending: Phase 0 deferred):** gold-set numbers improve
on at least overall F1. Per-CWE numbers will be noisy with 100-150
findings; that is fine. No regression in any per-CWE bucket beyond
5 points.

## Phase 2 — Real critic & calibration (Week 3-6)

**Largest single architectural change.** Must follow Phase 1.

**Status:** Done (2026-05-22). Sliced by capability rather than by
doc: docs 07 and 05 land together because implementing the graph
without a real critic would require a throwaway stub node. One
combined effort, six PRs in merge order:

- #59: per-finding `TriageState` and supporting models
  (`EvidenceBundle`, `CodeEvidence`, `ToolCallRecord`,
  `CheckmarxFinding`, `AnalystVerdict`, `CritiqueResult`).
- #60: per-finding subgraph skeleton and pure routing functions.
- #61: stateless research node (each LLM turn rebuilt from system
  prompt plus CODE BANK plus only the last tool round; failed tool
  calls surfaced as `DO NOT RETRY`).
- #62: analyst and critic nodes (structured `AnalystVerdict` and
  `CritiqueResult` via `with_structured_output`).
- #63: self-consistency aggregation (plurality vote with adaptive
  sampling; `agreement_rate` blended with `evidence_strength` for
  the final confidence).
- #64: cutover. `SASTTriageAgent.analyze_single_finding` builds a
  `TriageState` and calls `per_finding_graph.ainvoke`. Removed
  `MAX_ANALYSIS_ITERATIONS`, `verify_analysis`,
  `submit_triage_decision`, TRIAGE prompts and the manual loop.

A live-LLM smoke test against real Gemini is the next gating
activity. Until then the structured-output behavior of the analyst
(`Optional[bool]`) and the critic (enum decision) is unverified
against the real model.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `07-langgraph-and-stateless.md` | 5-7 days | Migrate per-finding loop to LangGraph |
| 2 | `05-critic-and-self-consistency.md` | 5-7 days | Separate critic LLM + N-sample voting |

**Ship gate (pending: Phase 0 deferred):** the high-confidence false
negative failure mode is gone (verify on the gold-set that no
finding reported at confidence at or above 0.9 is a false negative).
Verdict stability re-run at or above 95%.

## Phase 3 — Better code retrieval (Week 7-8)

**Independent of Phase 2 in principle**, but the benefit is most
visible once the critic loop exists.

**Status:** Not started.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `08-code-retrieval.md` | 3-5 days | Dataflow-guided extraction + whole-file fallback |

**Ship gate (pending: Phase 0 deferred):** large files are no longer
read whole; no per-CWE recall regression vs the pre-retrieval
baseline. (Token savings show up mainly on large files, which the
gold-set may under-represent.)

## Phase 4 — Scale features (Week 9-12)

**Required for production deployment** at scale (large application portfolios).

**Status:** Not started.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `09-finding-clustering.md` | 7-10 days | Cluster + representative analysis |

**Ship gate (pending):** on a synthetic cluster-heavy dataset, total
LLM calls drop in proportion to cluster sizes, and propagated
verdicts match full per-finding analysis on the same members.

## Phase 5 — Hygiene (Week 12-13)

**Last, but not optional.**

**Status:** Not started. A scoped shipping-docs cleanup is being run
ahead of this phase to support the first live-LLM smoke test; that
work targets `docs/` on `dev` and does not subsume the full Phase 5
hygiene pass, which also covers dead-code removal and final
placeholder tuning.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `11-cleanup-and-docs.md` | 3-5 days | README, docs/, dead-code removal |

**Ship gate (pending):** a new contributor can read the docs and
understand the system without reading source code.

## Dependency graph

Status markers: `[D]` done, `[X]` deferred, `[ ]` not started.

```
       02 (gold-set)                       [X]
              │
              ▼
   ┌───────── 03, 04, 06, 10 ───────── Phase 1 [D]
   │              │
   │              ▼
   │         07 + 05 (combined)       ─── Phase 2 [D]
   │          │
   │          ▼
   │         08 (code retrieval)      ─── Phase 3 [ ]
   │          │
   │          ▼
   │         09 (clustering)          ─── Phase 4 [ ]
   │          │
   │          ▼
   └────────── 11 (cleanup)           ─── Phase 5 [ ]
```

Phase 2 collapses docs 07 and 05 into one combined step because
implementing the graph without a real critic would require a
throwaway stub. See "Deviations from the original plan" below.

## Per-phase decision points

After each phase ships, before starting the next:

1. **Run the full gold-set benchmark.** Numbers in
   `benchmark/results/<date>_<phase>.json`.
2. **Did the ship-gate metric move in the right direction?**
   - Yes: continue to next phase.
   - No: diagnose. If the change was structural and didn't help,
     consider rolling it back. *Do not paper over a flat or
     regressed metric by bundling on more changes.*
3. **Any per-CWE regression worse than -5 F1 points?** Triage the
   regression. Most likely cause: a new checklist over-corrected.

**Status note (2026-05-27):** these decision points have not been
applied between Phases 1 and 2 because Phase 0 (the gold-set) is
deferred. They remain the gating procedure once a gold-set exists.

## Deviations from the original plan

Recorded so the rationale is preserved.

1. **Phase 0 deferred.** Gold-set construction is user-owned and
   has not been scheduled. Phases 1 and 2 shipped without baseline
   numbers; the ship-gate metrics they describe remain pending.
2. **Phase 2 sliced by capability, not by doc.** The roadmap orders
   doc 07 (LangGraph) then doc 05 (critic and self-consistency).
   Implementing them in that order would have required a throwaway
   stub critic node, since the graph wiring is what holds the
   critic in place. They were combined into a single six-PR effort
   so that the graph and the real critic land together.
3. **Doc 04 split across two PR clusters.** PRs #55 and #56
   delivered the mandatory five-step analysis protocol and the
   benchmark classification/disposition split. PRs #57 and #58
   delivered the CWE checklist pipeline and the top-5 content.
   Same scope, two clean review surfaces.
4. **Ship gates pending, not skipped.** The per-phase decision
   points above still apply once a gold-set exists. Nothing in the
   merged code base has been validated against a gold-set baseline
   yet.
5. **Scoped docs cleanup ahead of Phase 5.** A targeted pass over
   `docs/` on `dev` is running before Phase 3 so the documentation
   reflects the current graph-based flow ahead of the first live
   smoke test. The full Phase 5 hygiene pass (including dead-code
   removal and placeholder calibration) still happens at the end.

## Risks and mitigations

Status reflects the merged code base as of 2026-05-27.

| Risk | Probability | Mitigation | Status |
|---|---|---|---|
| Phase 2 critic loop has latency that breaks user-facing flows | Medium | Per-finding subgraph is already async; verify P95 latency on gold-set | Not evaluated; awaits live runs |
| `langchain-google-genai` Gemini 2.5 Pro structured-output and tool-calling quirks | Medium | Phase 1 step 1 includes before/after gold-set comparison; if it regresses, defer migration | Open. Migration shipped; structured output (analyst `Optional[bool]`, critic enum) and tool-calling against real Gemini are not yet validated. First live smoke test is the immediate next step |
| Clustering is more complex than estimated and bleeds into Phase 5 | Medium-High | Time-box Phase 4 at 2 weeks; if not done, simplify (e.g. queryName-only clustering) | Open; Phase 4 not started |
| Gold-set is too small to measure per-CWE changes confidently | High | Acknowledged; track only overall metrics until gold-set grows | Open and intensified: no gold-set exists yet |
| Self-consistency adds too much cost | Medium | N is configurable per-finding; start at N=3, drop to N=1 for high-agreement cases | Mitigation in place: `INITIAL_SAMPLES=2`, `DEFAULT_SAMPLES=3`, adaptive sampling stops on majority. Cost not measured yet |
| Structured output schemas (`AnalystVerdict.is_vulnerable: Optional[bool]`, `CritiqueResult.decision` enum) round-trip incorrectly through Gemini | Medium | Surfaced by the first live finding run; if it triggers, narrow the schema or post-validate the dict | Open; only ever exercised against mocks |

## Effort totals

Original plan:

- Phase 0: 3-5 days
- Phase 1: 10-14 days (includes the full subagent-authored checklist set)
- Phase 2: 10-14 days
- Phase 3: 3-5 days
- Phase 4: 7-10 days
- Phase 5: 3-5 days

**Total: roughly 8-11 working weeks of focused implementation.**

Realistic calendar time including reviews, gold-set growth, and
real-world interruptions: ~3 months.

### Actuals to date

| Phase | Original estimate | Actual elapsed | Notes |
|---|---|---|---|
| 0 | 3-5 days | Deferred | Pending user-owned gold-set work |
| 1 | 10-14 days | <1 day | PRs #52 to #58 (all merged 2026-05-22) |
| 2 | 10-14 days | <1 day | PRs #59 to #64 (all merged 2026-05-22); sliced by capability |
| 3 | 3-5 days | -- | Not started |
| 4 | 7-10 days | -- | Not started |
| 5 | 3-5 days | -- | Not started |

The Phase 1 and Phase 2 elapsed figures reflect continuous PR work
that landed inside a single calendar day. They are not a useful
baseline for re-estimating the remaining phases.
