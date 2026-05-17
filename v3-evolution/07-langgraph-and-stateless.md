# 07 — LangGraph per-finding subgraph + stateless prompt rebuild

> Scope: migrate the per-finding control flow from a manual
> Python `for` loop (current `agent.py:analyze_single_finding`) to
> a LangGraph state machine. While doing so, switch the researcher
> to a stateless prompt-rebuild pattern (no replay of message
> history; the system prompt is built fresh each turn with an
> accumulated "evidence so far" block).
>
> Depends on: `03-llm-backend.md`,
> `04-prompt-redesign.md`,
> `05-critic-and-self-consistency.md`.

## Goal

The per-finding control flow becomes a real LangGraph
`StateGraph`. The researcher uses stateless prompt rebuild (the
"CODE BANK" pattern from sast-ai-workflow). The outer pipeline
stays plain Python.

## Why LangGraph for this

The per-finding flow is no longer linear once we have a critic:

- After analyst → critic decides one of three branches.
- `NEEDS_MORE_RESEARCH` loops back to researcher with a list of
  required information.
- `REANALYZE` loops back to analyst with critic feedback prepended.
- `APPROVED` exits the subgraph.

Hand-rolling this in a `while True` loop becomes brittle fast.
LangGraph gives us:

- Explicit conditional edges (`add_conditional_edges`).
- Stateful checkpointing (replay a finding from a saved state for
  debugging).
- Cleanly inspectable graph topology.
- Circuit-breaker logic in one place, not scattered.

## Why NOT NeMo Agent Toolkit

`sast-ai-workflow` uses `nvidia-nat` for workflow registration,
builder patterns, CLI runners. Skip it:

- NAT adds heavyweight abstractions over LangGraph that we don't
  need (we have one workflow, not a registry of them).
- Extra dependencies (`nvidia-nat`, `nvidia-nat-langchain`).
- Coupled to NVIDIA's ecosystem.

Plain `langgraph` is sufficient.

## State definition

`sast_triage/graph/state.py`:

```python
from pydantic import BaseModel, Field
from typing import Optional

class TriageState(BaseModel):
    # Input
    finding: CheckmarxFinding
    checklist: ChecklistDocument

    # Research state
    evidence: EvidenceBundle = Field(default_factory=EvidenceBundle)
    research_iterations: int = 0
    failed_tool_calls: list[ToolCallRecord] = []

    # Analyst state
    samples: list[AnalystVerdict] = []
    current_sample_idx: int = 0

    # Critic state
    last_critique: Optional[CritiqueResult] = None
    reanalysis_count: int = 0

    # Termination
    stop_reason: Optional[Literal[
        "approved", "max_research", "max_reanalysis", "no_progress"
    ]] = None

    # Final
    verdict: Optional[TriageDecision] = None
```

## Graph topology

`sast_triage/graph/build.py`:

```python
from langgraph.graph import StateGraph, END

def build_per_finding_graph():
    g = StateGraph(TriageState)

    g.add_node("research", research_node)
    g.add_node("analyst", analyst_node)
    g.add_node("critic", critic_node)
    g.add_node("aggregate", aggregate_node)

    g.set_entry_point("research")

    g.add_edge("research", "analyst")

    g.add_conditional_edges(
        "analyst",
        lambda s: "critic" if s.samples else "research",
    )

    g.add_conditional_edges(
        "critic",
        route_from_critic,  # → "research" | "analyst" | "aggregate"
    )

    g.add_conditional_edges(
        "aggregate",
        lambda s: END if s.verdict else "research",  # tiebreak path
    )

    return g.compile()
```

### `route_from_critic` (the heart of the graph)

```python
def route_from_critic(state: TriageState) -> str:
    crit = state.last_critique
    # Circuit breakers first
    if state.research_iterations >= MAX_RESEARCH_ITERATIONS:
        state.stop_reason = "max_research"
        return "aggregate"
    if state.reanalysis_count >= MAX_REANALYSIS_LOOPS:
        state.stop_reason = "max_reanalysis"
        return "aggregate"

    # Critic decision
    if crit.decision == "APPROVED":
        # this sample is done; do we need more samples?
        if len(state.samples) < target_samples_for(state):
            return "analyst"  # next sample
        state.stop_reason = "approved"
        return "aggregate"
    elif crit.decision == "NEEDS_MORE_RESEARCH":
        return "research"
    elif crit.decision == "REANALYZE":
        state.reanalysis_count += 1
        return "analyst"
```

Self-consistency sample-count target (`target_samples_for`) is
computed adaptively per `05-critic-and-self-consistency.md`.

## Stateless prompt rebuild (researcher only)

Currently the researcher's full message history is replayed every
turn (`agent.py:201,309`). At 15+ tool calls this is 30K+ tokens of
historical noise.

Replace with stateless rebuild — each researcher turn sees only:

1. **System message** (built fresh each turn):
   - Role description
   - The finding (re-injected, not replayed)
   - The checklist
   - The current EvidenceBundle (CODE BANK)
   - Failed tool calls log ("don't retry these with same args")
2. **Tool messages** for any tools just called (current turn only).

Implementation pattern (LangGraph middleware):

```python
async def research_node(state: TriageState) -> dict:
    # Build the stateless prompt fresh from state
    system_msg = build_research_system_prompt(state)
    code_bank_msg = format_code_bank(state.evidence)

    # Only the last tool round-trip from message history
    last_round = extract_last_tool_round(state)

    messages = [
        SystemMessage(content=system_msg),
        SystemMessage(content=code_bank_msg),
        *last_round,
    ]

    response = await researcher_llm.ainvoke(messages)
    # Process tool calls; update state.evidence; return delta
    ...
```

`build_research_system_prompt(state)` and `format_code_bank(state)`
are pure functions of the state. The model never sees its own raw
chat history — only structured state.

This is the pattern sast-ai-workflow's
`stateless_model_middleware` implements. It is essential for long
research phases on Gemini 2.5 Pro (context rot — Chroma 2025
study).

## Why ONLY researcher uses stateless

Analyst and critic each run once per sample. They don't have the
"30 turns of history" problem. Sticking with normal message
construction (system + user) is simpler.

## Outer pipeline integration

`sast_triage/agent.py` (or its successor):

```python
async def analyze_single_finding(self, result_hash: str) -> TriageDecision:
    finding = await self.fetch_finding(result_hash)
    checklist = select_checklist(finding.queryName, finding.cwe)

    state = TriageState(finding=finding, checklist=checklist)
    final_state = await self.per_finding_graph.ainvoke(state)
    return final_state.verdict
```

The outer pipeline (cluster → for each → write back) stays plain
Python.

## Circuit breakers

Same as sast-ai-workflow's, calibrated for our use case:

```python
MAX_RESEARCH_ITERATIONS = 5
MAX_REANALYSIS_LOOPS = 2
MAX_TOOL_CALLS_PER_RESEARCH = 10
NO_PROGRESS_THRESHOLD = 2  # consecutive iterations with no new evidence
```

If any limit is hit, route to `aggregate` with a recorded
`stop_reason`. The aggregator handles `stop_reason != "approved"`
by:

- Routing the finding to `PROPOSED_NOT_EXPLOITABLE` if a tentative
  verdict exists.
- Routing to `REFUSED` if no verdict can be assembled.

## Implementation steps

1. Add `langgraph` to `requirements.txt`.
2. Create `sast_triage/graph/` directory with `state.py`, `nodes.py`,
   `build.py`, `routing.py`.
3. Implement each node (research, analyst, critic, aggregate) as a
   pure async function over `TriageState`.
4. Implement `route_from_critic` and other conditional-edge
   functions.
5. Implement stateless-rebuild for the research node.
6. Wire `agent.py:analyze_single_finding` to call the compiled
   graph.
7. Delete the old manual ReAct loop (`agent.py:195-321`).
8. Update tests.

## Acceptance criteria

- Per-finding flow runs entirely through the LangGraph graph.
- Old `for iteration in range(max_iterations)` loop removed.
- Stateless rebuild verified on long research phases (gold-set
  finding with > 10 file reads — researcher's input token count
  per turn stays under 8K).
- Verdict stability re-run rate (now measurable via Phase 0
  metrics) hits ≥ 95%.
- Circuit breakers verified by deliberate failure tests (no
  reachable verdict → routed to `REFUSED` cleanly).

## Risks / rollback

- **Risk:** stateless rebuild loses important "I tried X and it
  failed" context. **Mitigation:** the failed-tool-calls log in
  state is explicitly fed into the system prompt every turn.
- **Risk:** LangGraph version churn breaks the graph. **Mitigation:**
  pin `langgraph` to a specific minor version in `requirements.txt`;
  upgrades go through a benchmark check.
- **Rollback:** the old loop is large but bounded; reverting is a
  single-commit revert if the graph proves unworkable.

## Out of scope

- LangGraph checkpointing / replay for debugging. Useful future
  feature; not Phase 2.
- Streaming intermediate states to a UI. v3 has no UI.
- Human-in-the-loop interrupt nodes. v3's HITL is async (review
  queue), not blocking.
