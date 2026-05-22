# 01 — Target architecture

> Scope: the v3 architecture, diagrammed. This is the destination;
> the other v3-evolution docs describe how to get there incrementally.
>
> Depends on: `00-overview.md`.

## High-level shape

```
   ┌─────────────────────────────────────────────────────────────┐
   │                        Outer pipeline                       │
   │                                                             │
   │   Fetch Checkmarx ──▶ Cluster ──▶ For each cluster ──▶ Aggregate
   │   findings            findings    (representative)        verdicts
   │                                          │                  │
   │                                          ▼                  ▼
   │                              ┌───────────────────────┐   Write to
   │                              │ Per-finding subgraph  │   output files
   │                              └───────────────────────┘
   └─────────────────────────────────────────────────────────────┘
```

The outer pipeline is plain Python (LangGraph adds no value for
linear flow). The per-finding subgraph is LangGraph.

## Per-finding subgraph

```
                       ┌────────────────────────┐
                       │  EvidenceBundle init   │
                       │  (finding + checklist) │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │     Researcher LLM     │◀──────────────┐
                       │  - tools only          │               │
                       │  - no verdict          │               │
                       │  - hard cap N tools    │               │
                       └───────────┬────────────┘               │
                                   │                            │
                                   ▼                            │
                       ┌────────────────────────┐               │
                       │      Analyst LLM       │◀──────┐       │
                       │  - sees EvidenceBundle │       │       │
                       │  - mandatory steps     │       │       │
                       │  - structured verdict  │       │       │
                       └───────────┬────────────┘       │       │
                                   │                    │       │
                                   ▼                    │       │
                       ┌────────────────────────┐       │       │
                       │      Critic LLM        │       │       │
                       │  - adversarial role    │       │       │
                       │  - T=0.5-0.7           │       │       │
                       └───────────┬────────────┘       │       │
                                   │                    │       │
                          ┌────────┼────────┐           │       │
                          │        │        │           │       │
                       APPROVED  REANALYZE  MORE-RESEARCH       │
                          │        │        │                   │
                          ▼        └────────┼───────────────────┘
                    Self-consistency        │ (loop bounded)
                       aggregator           │
                          │                 │
                          ▼                 │
                    Final verdict + ◀───────┘
                    calibrated confidence
```

Three LLM roles, three different system prompts, all on Gemini 2.5 Pro.

## The three LLM roles

### Researcher
- **Tools:** `extract_function` (primary), `read_file` (fallback),
  `search_in_files`, `list_directory`. No `submit_*` tools.
- **Output:** structured `EvidenceBundle` (no verdict field by
  schema).
- **Temperature:** 0.1 (stable tool calls).
- **Hard cap:** 10 tool calls per research phase; on cap, force
  hand-off to analyst with whatever was gathered.
- **System prompt:** "Gather and report code evidence. Do not
  decide if the finding is exploitable."

### Analyst
- **Tools:** none. Pure LLM call.
- **Input:** `EvidenceBundle` + per-CWE checklist.
- **Output:** structured `AnalystVerdict { verdict, confidence,
  reasoning, evidence_refs, open_questions }`.
- **Temperature:** 0.1 for the primary sample; 0.3 and 0.5 for the
  self-consistency replicas (`ANALYST_TEMPERATURES = [0.1, 0.3, 0.5]`,
  see `05-critic-and-self-consistency.md`).
- **System prompt:** mandatory step-by-step protocol (see
  `04-prompt-redesign.md`).

### Critic
- **Tools:** none.
- **Input:** `AnalystVerdict` + `EvidenceBundle` + checklist.
- **Output:** `CritiqueResult { decision, gaps,
  required_information }` where `decision` is one of `APPROVED`,
  `NEEDS_MORE_RESEARCH`, `REANALYZE`.
- **Temperature:** 0.5-0.7 (defeat sycophancy).
- **System prompt:** adversarial — "Find the weakest point. Cite
  specific code lines for every agreement."

## State shape (Pydantic, see `07-langgraph-and-stateless.md`)

```python
class TriageState(BaseModel):
    finding: CheckmarxFinding
    checklist: ChecklistDocument

    # Researcher state
    evidence: EvidenceBundle
    tools_used: list[ToolCall]
    research_iterations: int = 0

    # Analyst state
    samples: list[AnalystVerdict] = []

    # Critic state
    critiques: list[CritiqueResult] = []
    reanalysis_count: int = 0

    # Final
    verdict: TriageDecision | None = None
```

## Self-consistency aggregation

After the critic approves an `AnalystVerdict`, the system runs N-1
additional analyst+critic passes (N=3 default, configurable per
finding complexity). Aggregation produces the two output fields (see
`06-output-model.md`); it never sets the disposition directly:

- **`is_vulnerable`** is the plurality classification across samples
  (a strict majority exploitable gives `true`; a strict majority
  non-exploitable gives `false`; no majority, or all samples
  abstained, gives `null`).
- **`agreement_rate`** is the winning-class count divided by the
  number of samples that produced a classification.
- **`confidence` = 0.7 × agreement_rate + 0.3 × evidence_strength**,
  not the model's self-report. Self-reported confidence is logged as
  a secondary diagnostic only.
- **`suggested_state` = derive_state(is_vulnerable, confidence)**.

So agreement feeds confidence, and confidence with the classification
feeds the disposition. A leaning-exploitable finding is always
`CONFIRMED`, even at low agreement (positives are never softened); a
leaning-non-exploitable finding below the confidence threshold becomes
`PROPOSED_NOT_EXPLOITABLE`; an even split (`is_vulnerable=null`)
becomes `REFUSED` for human attention.

## Outer pipeline detail

- **Fetch:** unchanged (`utils/checkmarx_helpers.py`).
- **Cluster:** new — by `(queryName, source_fingerprint,
  sink_fingerprint)`. See `09-finding-clustering.md`.
- **For each cluster, representative:** runs the full per-finding
  subgraph above.
- **For each non-representative:** runs a cheap pattern-match
  validation (single LLM call) against the representative's verdict.
- **Aggregate & emit:** new — assembles the two-field output and
  writes results to the local output files. The tool does not write
  back to Checkmarx (read-only; see `06-output-model.md`).

## Determinism stance

T=0 doesn't give bit-identical outputs (lack of batch invariance in
cloud LLMs). The aim is *stable verdicts via aggregation*, not
deterministic outputs. The self-consistency layer is what gives
stability. See `redesign-analysis.md` §2.3 last bullet for citation.

## Concurrency and rate limiting (open consideration)

The design multiplies LLM calls per finding (N samples, each with a
research loop, an analyst pass and a critic pass, plus reanalysis
loops), and a clustering validation call per propagated member. Run
across many findings this is a large volume of concurrent calls
against a single backend.

This is not a blocker for building the redesign and is out of scope
for the core architecture, but it must be handled before large-scale
production runs: a global concurrency cap, backoff on rate-limit
responses and a per-run budget guard. Captured here so it is not
lost. The per-sample work already runs under asyncio, so the cap is
the main missing piece.

## What's removed

- The single ReAct loop in `agent.py:analyze_single_finding`.
- The `verify_analysis` self-check tool.
- Phoenix tracing (`sast_triage/tracing.py`).

What stays:
- The Checkmarx integration, the CLI, the logging system, the
  Pydantic verdict model (extended), the path-validation helpers,
  the preprocessing pipeline.
