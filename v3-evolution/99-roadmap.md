# 99 — Phased rollout & sequencing

> Scope: the order in which the v3-evolution implementation docs
> should be executed, with dependencies, effort estimates, and
> per-phase ship gates.
>
> Depends on: every other v3-evolution doc.

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

| # | Doc | Effort |
|---|---|---|
| 1 | `02-gold-set-benchmark.md` | 3-5 days |

**Ship gate:** gold-set committed; current v2 code benchmarked
against it; baseline numbers recorded. Even if the baseline numbers
are uncomfortable, write them down — they're the floor.

## Phase 1 — Cheap structural wins (Week 1-2)

**Blocks Phase 2.** Independent of each other; can be parallelized
across implementers if needed.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `03-llm-backend.md` | 1 day | langchain-google-genai migration; unblocks AI Studio dev |
| 2 | `04-prompt-redesign.md` (checklists + steps) | 5-7 days | Full CWE checklist set (subagent-authored) + mandatory analysis steps |
| 3 | `06-output-model.md` | 2 days | Two-field output (classification + disposition); read-only |
| 4 | `10-phoenix-removal.md` | 0.5 day | Clean-up |

**Ship gate:** gold-set numbers improve on at least overall F1.
Per-CWE numbers will be noisy with 100-150 findings; that's fine.
No regression in any per-CWE bucket > 5 points.

## Phase 2 — Real critic & calibration (Week 3-6)

**Largest single architectural change.** Must follow Phase 1.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `07-langgraph-and-stateless.md` | 5-7 days | Migrate per-finding loop to LangGraph |
| 2 | `05-critic-and-self-consistency.md` | 5-7 days | Separate critic LLM + N-sample voting |

**Ship gate:** the high-confidence-FN failure mode is gone — verify
on the gold-set that no finding reported at confidence ≥ 0.9 is a
false negative. Verdict stability re-run ≥ 95%.

## Phase 3 — Better code retrieval (Week 7-8)

**Independent of Phase 2 in principle**, but the benefit is most
visible once the critic loop exists.

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `08-code-retrieval.md` | 3-5 days | Dataflow-guided extraction + whole-file fallback |

**Ship gate:** large files are no longer read whole; no per-CWE
recall regression vs the pre-retrieval baseline. (Token savings show
up mainly on large files, which the gold-set may under-represent.)

## Phase 4 — Scale features (Week 9-12)

**Required for production deployment** at scale (large application portfolios).

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `09-finding-clustering.md` | 7-10 days | Cluster + representative analysis |

**Ship gate:** on a synthetic cluster-heavy dataset, total LLM calls
drop in proportion to cluster sizes, and propagated verdicts match
full per-finding analysis on the same members.

## Phase 5 — Hygiene (Week 12-13)

**Last, but not optional.**

| # | Doc | Effort | Notes |
|---|---|---|---|
| 1 | `11-cleanup-and-docs.md` | 3-5 days | README, docs/, AGENTS.md, archive v2-evolution |

**Ship gate:** new contributor can read the docs and understand
the system without reading source code.

## Dependency graph

```
       02 (gold-set)
              │
              ▼
   ┌───────── 03, 04, 06, 10 ───────── Phase 1
   │              │
   │              ▼
   │          ┌─ 07 ──┐
   │          │       │
   │          │       ▼
   │          │      05 ──────────────── Phase 2
   │          │
   │          ▼
   │         08 (code retrieval)     ──── Phase 3
   │          │
   │          ▼
   │         09 (clustering)         ──── Phase 4
   │          │
   │          ▼
   └────────── 11 (cleanup)          ──── Phase 5
```

## Per-phase decision points

After each phase ships, before starting the next:

1. **Run the full gold-set benchmark.** Numbers in
   `benchmark/results/<date>_<phase>.json`.
2. **Did the ship-gate metric move in the right direction?**
   - Yes → continue to next phase
   - No → diagnose. If the change was structural and didn't help,
     consider rolling it back. *Do not paper over a flat or
     regressed metric by bundling on more changes.*
3. **Any per-CWE regression worse than -5 F1 points?** Triage the
   regression. Most likely cause: a new checklist over-corrected.

## Risks and mitigations

| Risk | Probability | Mitigation |
|---|---|---|
| Phase 2 critic loop has latency that breaks user-facing flows | Medium | Per-finding subgraph is already async; verify P95 latency on gold-set |
| `langchain-google-genai` 4.0 has Gemini 2.5 Pro tool-calling quirks | Medium | Phase 1 step 1 includes before/after gold-set comparison; if it regresses, defer migration |
| Clustering is more complex than estimated and bleeds into Phase 5 | Medium-High | Time-box Phase 4 at 2 weeks; if not done, simplify (e.g. queryName-only clustering) |
| Gold-set is too small to measure per-CWE changes confidently | High | Acknowledged; track only overall metrics until gold-set grows |
| Self-consistency adds too much cost | Medium | N is configurable per-finding; start at N=3, drop to N=1 for high-agreement cases |

## Effort totals

- Phase 0: 3-5 days
- Phase 1: 10-14 days (includes the full subagent-authored checklist set)
- Phase 2: 10-14 days
- Phase 3: 3-5 days
- Phase 4: 7-10 days
- Phase 5: 3-5 days

**Total: roughly 8-11 working weeks of focused implementation.**

Realistic calendar time including reviews, gold-set growth, and
real-world interruptions: ~3 months.
