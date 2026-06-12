# Per-finding header and confidence transparency in the session-log viewer

- Date: 2026-06-11
- Status: approved (design), pending spec review
- Topic: surface a per-finding summary in `viewer/`, with a transparent breakdown
  of how each finding's confidence and disposition were produced.

## Problem

The session-log viewer has no per-finding summary. When a finding is selected
it highlights the table row, renders the topology and traversal and filters the
timeline. The verdict and its reasoning are only reachable by scrolling the
timeline to the `finding_complete` row and clicking it to populate the
inspector. Three concrete gaps follow from this:

1. **Confidence is opaque.** The final confidence is computed in
   `aggregate_samples` as `W * agreement_rate + (1 - W) * evidence_strength`,
   with a circuit-breaker cap and a threshold that decides the disposition. The
   logged `TriageDecision` records only `confidence`, `agreement_rate` and
   `sample_count`. `evidence_strength`, the weight, the pre-cap value and the
   per-sample votes are never logged, so the viewer cannot explain the number.

2. **The sample count misleads.** The findings table's `samples` column counts
   analyst LLM calls (`findingSampleCount`), and `reanalysis` is
   `analyst_visits - 1`. When the critic drives reanalysis, the analyst
   *replaces* the in-progress sample (`analyst.py`, `samples[-1] = verdict`), so
   a finding that reaches `MAX_REANALYSIS_LOOPS` can show three analyst calls
   while exactly one sample voted. The truthful count (`final_decision.sample_count`)
   sits in the log unused. The `reanalysis` heuristic is also wrong for a clean
   finding that took several fresh adaptive samples with no reanalysis.

3. **Context requires hunting.** Which checklist was used, the stop reason, the
   research and critic activity and the cost are all in the log but scattered
   across events.

## Goals

- A per-finding header card that answers "what was decided and why" at a glance,
  with the confidence arithmetic and the per-sample votes available on demand.
- Truthful sample and reanalysis figures in the findings table.
- The confidence breakdown logged by the agent as the single source of truth, so
  the viewer never reimplements aggregator math.

## Non-goals

- No change to the advisory output written to `output/`. The breakdown and
  per-sample votes are observability detail and live only in the session log.
- No reconstruction of overwritten reanalysis attempts. Their content stays
  browsable as `llm_call` rows in the timeline, as today.
- No calibration-curve or aggregate-plot features (those remain in the
  benchmark tooling).

## Decisions (resolved during brainstorming)

1. **Data source:** the agent logs the breakdown. The aggregator is the single
   source of truth; the viewer only renders.
2. **Header content:** all four blocks. A verdict line plus collapsible
   confidence breakdown, per-sample votes and process diagnostics.
3. **Placement:** a full-width card below the findings table and above the
   topology, with the verdict line always visible and the heavier blocks as
   collapsible `<details>` sections.
4. **Output files stay lean:** the breakdown is added to the `finding_complete`
   session-log event, not to `TriageDecision`.

## Design

### A. Agent side

#### New models (`sast_triage/agent_models.py`)

```
class SampleVote(BaseModel):
    is_vulnerable: Optional[bool]
    self_confidence: float          # the sample's pre-calibration self-report
    temperature: Optional[float]
    n_citations: int
    n_evidence_refs: int

class ConfidenceBreakdown(BaseModel):
    agreement_rate: Optional[float] # None below _MIN_CORROBORATING_SAMPLES
    evidence_strength: float
    agreement_weight: float         # CONFIDENCE_AGREEMENT_WEIGHT at compute time
    raw_confidence: float           # before the circuit-breaker cap
    cap_applied: bool               # whether _earned_confidence reduced it
    cap_value: float                # NON_CONVERGENT_CONFIDENCE_CAP
    final_confidence: float         # equals TriageDecision.confidence
    threshold: float                # CONFIDENCE_THRESHOLD
    sample_votes: List[SampleVote]
```

`SampleVote` is structural (counts, not content), so it is identical in `rich`
and `observability` modes.

#### Aggregator (`sast_triage/aggregator.py`)

`aggregate_samples` already computes every breakdown field as a local. Change its
return type from `TriageDecision` to `Tuple[TriageDecision, ConfidenceBreakdown]`.
All branches return both, including the empty-samples early return (a trivial
breakdown: `sample_votes=[]`, `evidence_strength=0.0`, `raw_confidence=0.0`,
`final_confidence=0.0`). Field mapping:

- `agreement_rate`: the `tally` rate, or `None` when `len(samples) < _MIN_CORROBORATING_SAMPLES`, matching the existing decision field.
- `evidence_strength`: `compute_evidence_strength(samples)`, computed in every
  branch (including a split vote) for diagnostic value.
- `raw_confidence`: the value before `_earned_confidence`. Multi-sample:
  `W * agreement + (1 - W) * evidence`. Single sample: `(1 - W) * evidence`.
  Split vote: `0.0`.
- `cap_applied`: `True` when `_earned_confidence` lowered `raw_confidence`
  (negative verdict, `stop_reason != "approved"`, raw above the cap).
- `final_confidence`: `round(confidence, 4)`, equal to `decision.confidence`.
- `sample_votes`: one `SampleVote` per entry in `samples`, in order.

The `_build_justification` text is unchanged.

#### State and node (`graph/state.py`, `graph/aggregate.py`)

Add `confidence_breakdown: Optional[ConfidenceBreakdown] = None` to `TriageState`.
This is the one new state field, justified because it is a genuine output of the
aggregate node that the agent needs after the graph returns. `aggregate_node`
unpacks the tuple and returns
`{"verdict": decision, "confidence_breakdown": breakdown, "stop_reason": stop_reason}`.

#### Event (`session_log/events.py`)

`FindingCompleteEvent`: bump `v` from 1 to 2 and add two additive optional fields:

```
confidence_breakdown: Optional[Dict[str, Any]] = None
process_summary: Optional[Dict[str, Any]] = None   # see ProcessSummary below
```

`process_summary` carries the final process counters:

```
ProcessSummary:
    evidence_items_count: int
    failed_tool_calls_count: int
    reanalysis_count: int
    research_stall_streak: int
```

Both are optional so v1 logs and the error path parse unchanged.

#### Logger and agent (`session_log/session.py`, `agent.py`)

`emit_finding_complete` gains two keyword params,
`confidence_breakdown: Optional[Dict]` and `process_summary: Optional[Dict]`,
defaulting to `None`, written straight onto the event.

In `analyze_finding`, after `ainvoke` returns the final state:

- read `result["confidence_breakdown"]` (the model set by the node) and dump it.
- build `ProcessSummary` from the final state: `reanalysis_count`,
  `research_stall_streak`, `len(evidence.items)`, `len(failed_tool_calls)`. The
  final state is read defensively; a test pins the shape `ainvoke` returns so the
  attribute access is verified rather than assumed.
- pass both dumps to `emit_finding_complete`.

The exception path (the hand-built `REFUSED` decision) passes `None` for both.

### B. Viewer side (`viewer/viewer.js`, `viewer/viewer.css`)

#### New header card

A `renderFindingHeader(tab, session, finding)` function, called from
`renderFlowAndTimeline` before `renderFlow`, only when a finding is selected.
Structure:

- **Verdict line (always visible):** state badge, final confidence,
  `is_vulnerable`, `CWE-<id>`, `checklist_id` and selection method (from the
  finding's `finding_start`), `stop_reason`, `"<sample_count> voted · <reanalysis_count> reanalysis loops"`, duration, total tokens.
- **Confidence breakdown (`<details>`):** the arithmetic spelled out, for example
  `0.7 x agreement(1.00) + 0.3 x evidence(0.34) = 0.80 raw -> cap 0.80 -> final 0.80`,
  then the `derive_state` reasoning (the threshold comparison that produced the
  disposition). When `confidence_breakdown` is absent (v1 logs), fall back to the
  decision's `confidence`, `agreement_rate` and `sample_count` with a
  "detailed breakdown not in this log" note.
- **Sample votes (`<details>`):** a table, one row per `SampleVote`
  (verdict, self-confidence, temperature, citation count, evidence-ref count).
  Absent in v1 logs: show "not available".
- **Process diagnostics (`<details>`):** evidence items, failed tool calls and
  stall streak (from `process_summary`); the critic decision trail and final
  `weakest_point` (derived from each critic `node_exit.state_writes.last_critique`,
  no agent change; if `state_writes` does not carry the full critique, fall back
  to the `last_critique_decision` values in later `node_enter` snapshots for the
  decision sequence); and a cost line (existing `finding_complete` fields).

All four blocks reuse the existing safe-DOM helpers (`el`, `renderKvTable`,
collapsible `<details>`). No `innerHTML`, consistent with the viewer's CSP.

#### Findings-table fixes

In `renderFindingsTable`:

- `samples` column: `final_decision.sample_count` when present, else the current
  `findingSampleCount` heuristic.
- `reanalysis` column: `process_summary.reanalysis_count` when present, else the
  current `analyst_visits - 1` heuristic.

The analyst-call count (`findingSampleCount`) is kept and shown in the header as
the "attempts" figure, so "1 voted / 3 attempts" is explicit.

#### Inspector

`inspectFindingComplete` reuses the same breakdown renderer, so clicking the
event shows identical detail.

### C. Tests

Test-first, next to the code under test.

- `sast_triage/tests` (aggregator): `aggregate_samples` returns a breakdown whose
  `final_confidence` equals `decision.confidence`, with correct
  `evidence_strength`, `raw_confidence` vs the cap, `agreement_weight` and
  `sample_votes`, across four cases: multi-sample agreement, single sample,
  split vote and capped negative dismissal. Plus the empty-samples early return.
- `sast_triage/tests` (agent_models): validation of `SampleVote` and
  `ConfidenceBreakdown`.
- `sast_triage/tests` (session_log): `emit_finding_complete` writes both new
  fields; a `finding_complete` line round-trips through
  `TypeAdapter(SessionLogEvent)` at `v=2`; omitting the fields still parses
  (v1 compatibility).
- `sast_triage/tests` (agent or graph): the shape of the final state returned by
  `ainvoke` is pinned so the `ProcessSummary` extraction is verified.

The viewer has no test harness; it is verified manually against a sample log, per
its "tool, not shipped feature" status.

### D. Docs

- `docs/session-log.md`: document `finding_complete` v2, the two new fields and
  the `SampleVote` / `ConfidenceBreakdown` / `ProcessSummary` shapes.
- `docs/session-log-viewer.md`: the new header card in the panes section, the
  corrected `samples` and `reanalysis` column semantics, the inspector note and
  the new fields in the coupling section.

## Edge cases

- **v1 logs:** all new fields optional; the header falls back to decision-only
  fields with a note. Table columns fall back to the old heuristics.
- **Observability mode:** `SampleVote` and the breakdown scalars are structural,
  so the header renders fully. Only the timeline's overwritten-attempt contents
  remain hashed, as today.
- **Error path:** `confidence_breakdown` and `process_summary` are `None`; the
  header shows the `REFUSED` verdict and the "not in this log" notes.
- **Split vote / REFUSED:** `is_vulnerable` is `None`, `raw_confidence` 0,
  `final_confidence` 0; the breakdown still lists the diverging `sample_votes`.

## Version bumps

- `finding_complete`: `v` 1 -> 2 (additive).
- No other event type changes. `node_enter` is untouched.

## Files touched

`agent_models.py`, `aggregator.py`, `graph/state.py`, `graph/aggregate.py`,
`session_log/events.py`, `session_log/session.py`, `agent.py`,
`viewer/viewer.js`, `viewer/viewer.css`, `docs/session-log.md`,
`docs/session-log-viewer.md`, and the corresponding test files.
