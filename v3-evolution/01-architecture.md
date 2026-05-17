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
   │                              ┌───────────────────────┐   Write back
   │                              │ Per-finding subgraph  │   to Checkmarx
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
- **Temperature:** 0.1 for the primary sample; 0.4 for self-
  consistency replicas.
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
finding complexity). Verdicts are aggregated:

| Agreement | Outcome |
|-----------|---------|
| N/N agree, all critic-approved | High-confidence verdict |
| (N-1)/N agree | Medium-confidence verdict |
| < (N-1)/N agree | `PROPOSED_NOT_EXPLOITABLE` → HITL |

**Confidence is `agreement_rate × evidence_strength`,** not the
model's self-report. Self-reported confidence is logged as a
secondary diagnostic only.

## Outer pipeline detail

- **Fetch:** unchanged from v2 (`utils/checkmarx_helpers.py`).
- **Cluster:** new — by `(queryName, sink_signature,
  source_signature)`. See `09-finding-clustering.md`.
- **For each cluster, representative:** runs the full per-finding
  subgraph above.
- **For each non-representative:** runs a cheap pattern-match
  validation (single LLM call) against the representative's verdict.
- **Aggregate & write back:** new — handles `PROPOSED_NOT_EXPLOITABLE`
  routing.

## Determinism stance

T=0 doesn't give bit-identical outputs (lack of batch invariance in
cloud LLMs). The aim is *stable verdicts via aggregation*, not
deterministic outputs. The self-consistency layer is what gives
stability. See `redesign-analysis.md` §2.3 last bullet for citation.

## What's gone vs v2

- The single ReAct loop in `agent.py:analyze_single_finding`.
- The `verify_analysis` self-check tool.
- Phoenix tracing (`sast_triage/tracing.py`).

What stays:
- The Checkmarx integration, the CLI, the logging system, the
  Pydantic verdict model (extended), the path-validation helpers,
  the preprocessing pipeline.
