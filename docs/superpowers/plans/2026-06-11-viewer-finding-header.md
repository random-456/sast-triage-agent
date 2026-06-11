# Per-finding Header and Confidence Transparency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a full-width per-finding header card to the session-log viewer that explains how each finding's confidence and disposition were produced, backed by a confidence breakdown the agent logs as the single source of truth.

**Architecture:** The aggregator (`aggregate_samples`) already computes every input to the confidence number; change it to also return a `ConfidenceBreakdown`. The aggregate node carries it out of the graph in `TriageState`, the agent logs it (plus a small process summary) on the `finding_complete` event (bumped to v2), and the viewer renders a header card with a verdict line and three collapsible blocks. Output files in `output/` are unchanged: the breakdown is observability detail and lives only in the session log.

**Tech Stack:** Python 3, Pydantic, LangGraph, pytest (asyncio_mode=auto). Vanilla JS viewer (no build step, CSP-restricted, textContent-only rendering).

Reference spec: `docs/superpowers/specs/2026-06-11-viewer-finding-header-design.md`.

All Python commands run inside the project venv: prefix with `source .venv/bin/activate`. Tests live in the top-level `tests/` directory.

---

## File structure

- `sast_triage/agent_models.py` — add `SampleVote` and `ConfidenceBreakdown` models.
- `sast_triage/aggregator.py` — `aggregate_samples` returns `(TriageDecision, ConfidenceBreakdown)`.
- `sast_triage/graph/state.py` — add `confidence_breakdown` field to `TriageState`.
- `sast_triage/graph/aggregate.py` — unpack and return the breakdown.
- `sast_triage/session_log/events.py` — `FindingCompleteEvent` v2 with two optional fields.
- `sast_triage/session_log/session.py` — `emit_finding_complete` accepts the two fields.
- `sast_triage/agent.py` — build the process summary, pass both into the event.
- `viewer/viewer.js` — header card, table column fixes, inspector reuse.
- `viewer/viewer.css` — header card styling.
- `docs/session-log.md`, `docs/session-log-viewer.md` — schema and viewer docs.
- Tests: `tests/test_agent_models.py`, `tests/test_aggregator.py`, `tests/test_graph_aggregate.py`, `tests/test_session_log_events.py`, `tests/test_session_log_session.py`, `tests/test_agent.py`.

---

### Task 1: Confidence-breakdown models

**Files:**
- Modify: `sast_triage/agent_models.py` (add two models after `TriageDecision`, around line 81)
- Test: `tests/test_agent_models.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_agent_models.py`. Also add `ConfidenceBreakdown` and `SampleVote` to the existing import from `sast_triage.agent_models` near line 11.

```python
class TestConfidenceBreakdownModels:
    """The aggregator's confidence breakdown and per-sample votes validate."""

    def test_sample_vote_counts_are_non_negative(self):
        from sast_triage.agent_models import SampleVote

        with pytest.raises(ValueError):
            SampleVote(
                is_vulnerable=True,
                self_confidence=0.9,
                temperature=0.1,
                n_citations=-1,
                n_evidence_refs=0,
            )

    def test_breakdown_defaults_sample_votes_to_empty(self):
        from sast_triage.agent_models import ConfidenceBreakdown

        bd = ConfidenceBreakdown(
            agreement_rate=None,
            evidence_strength=0.0,
            agreement_weight=0.7,
            raw_confidence=0.0,
            cap_applied=False,
            cap_value=0.8,
            final_confidence=0.0,
            threshold=0.85,
        )
        assert bd.sample_votes == []
        assert bd.agreement_rate is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_agent_models.py::TestConfidenceBreakdownModels -v`
Expected: FAIL with `ImportError: cannot import name 'ConfidenceBreakdown'` (or `SampleVote`).

- [ ] **Step 3: Write minimal implementation**

In `sast_triage/agent_models.py`, insert after the `TriageDecision` class (after line 80):

```python
class SampleVote(BaseModel):
    """One surviving voting sample, summarized for the confidence breakdown.

    Structural counts only (no content), so it is identical in rich and
    observability log modes.
    """

    is_vulnerable: Optional[bool] = Field(
        description="The sample's classification: True, False or None"
    )
    self_confidence: float = Field(
        ge=0.0, le=1.0, description="The sample's pre-calibration self-report"
    )
    temperature: Optional[float] = Field(
        default=None, description="Sampling temperature that produced the sample"
    )
    n_citations: int = Field(ge=0, description="Number of citation lines")
    n_evidence_refs: int = Field(ge=0, description="Number of evidence references")


class ConfidenceBreakdown(BaseModel):
    """The exact inputs that produced a finding's calibrated confidence.

    Logged on ``finding_complete`` so the viewer can explain the number
    without reimplementing the aggregator. ``final_confidence`` equals
    ``TriageDecision.confidence``.
    """

    agreement_rate: Optional[float] = Field(
        default=None, description="Vote agreement; None below the corroboration floor"
    )
    evidence_strength: float = Field(
        ge=0.0, le=1.0, description="0..1 grounding proxy from files and citations"
    )
    agreement_weight: float = Field(
        ge=0.0, le=1.0, description="CONFIDENCE_AGREEMENT_WEIGHT at compute time"
    )
    raw_confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence before the circuit-breaker cap"
    )
    cap_applied: bool = Field(
        description="Whether the non-convergent dismissal cap lowered confidence"
    )
    cap_value: float = Field(
        ge=0.0, le=1.0, description="NON_CONVERGENT_CONFIDENCE_CAP"
    )
    final_confidence: float = Field(
        ge=0.0, le=1.0, description="Final confidence; equals the decision's"
    )
    threshold: float = Field(
        ge=0.0, le=1.0, description="CONFIDENCE_THRESHOLD for the disposition"
    )
    sample_votes: List[SampleVote] = Field(
        default_factory=list, description="One entry per surviving voting sample"
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/test_agent_models.py -v`
Expected: PASS (all model tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add sast_triage/agent_models.py tests/test_agent_models.py
git commit -m "feat(models): add ConfidenceBreakdown and SampleVote"
```

---

### Task 2: Aggregator returns the breakdown

**Files:**
- Modify: `sast_triage/aggregator.py` (`aggregate_samples`, lines 127-182; imports lines 12-18)
- Modify: `sast_triage/graph/state.py` (add field, imports line 18-23)
- Modify: `sast_triage/graph/aggregate.py` (lines 18-23)
- Test: `tests/test_aggregator.py`, `tests/test_graph_aggregate.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_aggregator.py`:

```python
class TestConfidenceBreakdownOutput:
    """aggregate_samples returns the decision plus a transparent breakdown."""

    def test_returns_decision_and_breakdown_pair(self):
        decision, breakdown = aggregate_samples("h", [_v(True), _v(True)])
        assert decision.confidence == breakdown.final_confidence

    def test_breakdown_records_blend_inputs(self):
        # Two-thirds agreement, no evidence: raw = W * (2/3), no cap.
        decision, breakdown = aggregate_samples("h", [_v(True), _v(True), _v(False)])
        assert breakdown.agreement_rate == round(2 / 3, 4)
        assert breakdown.evidence_strength == 0.0
        assert breakdown.agreement_weight == CONFIDENCE_AGREEMENT_WEIGHT
        assert breakdown.raw_confidence == round(CONFIDENCE_AGREEMENT_WEIGHT * (2 / 3), 4)
        assert breakdown.cap_applied is False
        assert len(breakdown.sample_votes) == 3
        assert breakdown.sample_votes[0].is_vulnerable is True

    def test_breakdown_flags_applied_cap(self):
        decision, breakdown = aggregate_samples(
            "h", [_strong(False), _strong(False)], stop_reason="max_research"
        )
        assert breakdown.raw_confidence > breakdown.cap_value
        assert breakdown.cap_applied is True
        assert breakdown.final_confidence == NON_CONVERGENT_CONFIDENCE_CAP

    def test_single_sample_breakdown_has_no_agreement(self):
        decision, breakdown = aggregate_samples("h", [_v(True)])
        assert breakdown.agreement_rate is None
        assert len(breakdown.sample_votes) == 1

    def test_empty_samples_returns_trivial_breakdown(self):
        decision, breakdown = aggregate_samples("h", [])
        assert breakdown.sample_votes == []
        assert breakdown.final_confidence == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_aggregator.py::TestConfidenceBreakdownOutput -v`
Expected: FAIL with `ValueError: too many values to unpack` (aggregate_samples still returns a single `TriageDecision`).

- [ ] **Step 3: Edit the aggregator imports**

In `sast_triage/aggregator.py`, change the agent_models import (lines 13-18) to add the two models:

```python
from sast_triage.agent_models import (
    AnalystVerdict,
    ConfidenceBreakdown,
    SampleVote,
    SuggestedState,
    TriageDecision,
    derive_state,
)
```

- [ ] **Step 4: Add the sample-votes helper and rewrite `aggregate_samples`**

In `sast_triage/aggregator.py`, add this helper just above `aggregate_samples` (before line 127):

```python
def _sample_votes(samples: List[AnalystVerdict]) -> List[SampleVote]:
    """Summarize each surviving sample for the confidence breakdown."""
    return [
        SampleVote(
            is_vulnerable=s.is_vulnerable,
            self_confidence=s.confidence,
            temperature=s.sample_temperature,
            n_citations=len(s.citation_lines),
            n_evidence_refs=len(s.evidence_refs),
        )
        for s in samples
    ]
```

Replace the entire `aggregate_samples` function (lines 127-182) with:

```python
def aggregate_samples(
    result_hash: str,
    samples: List[AnalystVerdict],
    stop_reason: Optional[str] = None,
) -> Tuple[TriageDecision, ConfidenceBreakdown]:
    """Combine analyst samples into the final decision and its breakdown."""
    if not samples:
        decision = TriageDecision(
            resultHash=result_hash,
            is_vulnerable=None,
            confidence=0.0,
            suggested_state=SuggestedState.REFUSED,
            justification=(
                "No analyst samples were produced; manual review required."
            ),
            agreement_rate=None,
            sample_count=0,
        )
        breakdown = ConfidenceBreakdown(
            agreement_rate=None,
            evidence_strength=0.0,
            agreement_weight=CONFIDENCE_AGREEMENT_WEIGHT,
            raw_confidence=0.0,
            cap_applied=False,
            cap_value=NON_CONVERGENT_CONFIDENCE_CAP,
            final_confidence=0.0,
            threshold=CONFIDENCE_THRESHOLD,
            sample_votes=[],
        )
        return decision, breakdown

    votes = [s.is_vulnerable for s in samples]
    majority, agreement_rate, is_clear = tally(votes)
    evidence_strength = compute_evidence_strength(samples)
    corroborated = len(samples) >= _MIN_CORROBORATING_SAMPLES

    if is_clear:
        is_vulnerable: Optional[bool] = majority
        if corroborated:
            raw_confidence = (
                CONFIDENCE_AGREEMENT_WEIGHT * agreement_rate
                + (1 - CONFIDENCE_AGREEMENT_WEIGHT) * evidence_strength
            )
        else:
            # A single sample is not self-consistency: there is no agreement
            # signal, so confidence rests on evidence strength alone.
            raw_confidence = (1 - CONFIDENCE_AGREEMENT_WEIGHT) * evidence_strength
    else:
        # A split is never a confident dismissal: route to human attention.
        is_vulnerable = None
        raw_confidence = 0.0

    confidence = _earned_confidence(raw_confidence, is_vulnerable, stop_reason)
    reported_agreement = round(agreement_rate, 4) if corroborated else None

    decision = TriageDecision(
        resultHash=result_hash,
        is_vulnerable=is_vulnerable,
        confidence=round(confidence, 4),
        suggested_state=derive_state(is_vulnerable, confidence),
        justification=_build_justification(
            samples, is_vulnerable, agreement_rate, stop_reason
        ),
        agreement_rate=reported_agreement,
        sample_count=len(samples),
    )
    breakdown = ConfidenceBreakdown(
        agreement_rate=reported_agreement,
        evidence_strength=round(evidence_strength, 4),
        agreement_weight=CONFIDENCE_AGREEMENT_WEIGHT,
        raw_confidence=round(raw_confidence, 4),
        cap_applied=confidence < raw_confidence,
        cap_value=NON_CONVERGENT_CONFIDENCE_CAP,
        final_confidence=round(confidence, 4),
        threshold=CONFIDENCE_THRESHOLD,
        sample_votes=_sample_votes(samples),
    )
    return decision, breakdown
```

Note: `Tuple` is already imported on line 10. The `derive_state` call uses the unrounded `confidence`, matching the prior behavior.

- [ ] **Step 5: Add the state field**

In `sast_triage/graph/state.py`, add `ConfidenceBreakdown` to the agent_models import (lines 18-23):

```python
from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    ConfidenceBreakdown,
    CritiqueResult,
    TriageDecision,
)
```

Then add the field to `TriageState`, immediately after the `stop_reason` field (after line 79):

```python
    confidence_breakdown: Optional[ConfidenceBreakdown] = None
```

- [ ] **Step 6: Update the aggregate node**

Replace the body of `aggregate_node` in `sast_triage/graph/aggregate.py` (lines 18-23) with:

```python
async def aggregate_node(state: TriageState) -> Dict:
    stop_reason = compute_stop_reason(state)
    decision, breakdown = aggregate_samples(
        state.finding.resultHash, state.samples, stop_reason
    )
    return {
        "verdict": decision,
        "confidence_breakdown": breakdown,
        "stop_reason": stop_reason,
    }
```

- [ ] **Step 7: Update existing aggregate_samples call sites in tests**

The existing `test_aggregator.py` cases assign a single value; update them to unpack the pair:

Run: `sed -i '' 's/decision = aggregate_samples(/decision, _ = aggregate_samples(/' tests/test_aggregator.py`

Then add a breakdown assertion to `tests/test_graph_aggregate.py`. Add `ConfidenceBreakdown` to the `sast_triage.agent_models` import (lines 9-16), and append this test:

```python
async def test_real_aggregate_node_emits_confidence_breakdown():
    graph = build_per_finding_graph(
        research_node=_research,
        analyst_node=_analyst,
        critic_node=_critic,
        aggregate_node=aggregate_node,
    )
    result = await graph.ainvoke(
        {
            "finding": CheckmarxFinding(resultHash="h", cweID="89"),
            "checklist": load_checklist("sqli"),
        }
    )
    breakdown = result["confidence_breakdown"]
    assert isinstance(breakdown, ConfidenceBreakdown)
    assert breakdown.final_confidence == result["verdict"].confidence
    assert len(breakdown.sample_votes) == INITIAL_SAMPLES
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/test_aggregator.py tests/test_graph_aggregate.py -v`
Expected: PASS (all old and new cases).

- [ ] **Step 9: Commit**

```bash
git add sast_triage/aggregator.py sast_triage/graph/state.py sast_triage/graph/aggregate.py tests/test_aggregator.py tests/test_graph_aggregate.py
git commit -m "feat(aggregator): return a confidence breakdown alongside the decision"
```

---

### Task 3: finding_complete event v2

**Files:**
- Modify: `sast_triage/session_log/events.py` (`FindingCompleteEvent`, lines 232-244)
- Test: `tests/test_session_log_events.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_session_log_events.py`:

```python
def test_finding_complete_v2_carries_breakdown_and_summary(envelope):
    event = FindingCompleteEvent(
        **envelope,
        finding_id="abc",
        stop_reason="max_reanalysis",
        final_decision={"resultHash": "abc", "sample_count": 1},
        total_duration_ms=1000.0,
        confidence_breakdown={"final_confidence": 0.24, "sample_votes": []},
        process_summary={
            "evidence_items_count": 3,
            "failed_tool_calls_count": 0,
            "reanalysis_count": 2,
            "research_stall_streak": 0,
        },
    )
    assert event.v == 2
    _roundtrip(event)


def test_finding_complete_v1_line_without_new_fields_parses(envelope):
    # A pre-v2 log line omits the new fields; it must still parse.
    event = FindingCompleteEvent(
        **envelope,
        finding_id="abc",
        stop_reason="approved",
        final_decision={"resultHash": "abc"},
        total_duration_ms=1000.0,
    )
    assert event.confidence_breakdown is None
    assert event.process_summary is None
    _roundtrip(event)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_session_log_events.py::test_finding_complete_v2_carries_breakdown_and_summary -v`
Expected: FAIL with `ValidationError` (unexpected keyword `confidence_breakdown`, since the model has `extra="forbid"` and `v` is still 1).

- [ ] **Step 3: Edit the event model**

In `sast_triage/session_log/events.py`, edit `FindingCompleteEvent` (lines 232-244): change `v` to 2 and add the two fields after `final_decision`:

```python
class FindingCompleteEvent(_EventBase):
    type: Literal["finding_complete"] = "finding_complete"
    v: int = 2
    finding_id: str
    stop_reason: Optional[str] = None
    final_decision: Dict[str, Any]
    confidence_breakdown: Optional[Dict[str, Any]] = None
    process_summary: Optional[Dict[str, Any]] = None
    total_duration_ms: float
    per_node_visit_counts: Dict[str, int] = Field(default_factory=dict)
    per_node_durations_ms: Dict[str, float] = Field(default_factory=dict)
    per_node_token_totals: Dict[str, TokenTotals] = Field(default_factory=dict)
    llm_calls_count: int = 0
    tool_calls_count: int = 0
    total_tokens: TokenTotals = Field(default_factory=TokenTotals)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/test_session_log_events.py -v`
Expected: PASS (old and new). The existing `test_finding_complete_aggregates_default_to_empty` still passes (new fields default to `None`).

- [ ] **Step 5: Commit**

```bash
git add sast_triage/session_log/events.py tests/test_session_log_events.py
git commit -m "feat(session-log): finding_complete v2 with confidence breakdown and process summary"
```

---

### Task 4: Logger and agent plumbing

**Files:**
- Modify: `sast_triage/session_log/session.py` (`emit_finding_complete`, lines 173-201)
- Modify: `sast_triage/agent.py` (typing import line 11; `analyze_finding` around lines 289-298; add a module-level helper)
- Test: `tests/test_session_log_session.py`, `tests/test_agent.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_session_log_session.py`:

```python
def test_finding_complete_carries_breakdown_and_process_summary(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config=_agent_config())
    logger_rich.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    logger_rich.emit_finding_complete(
        finding_id="abc",
        stop_reason="max_reanalysis",
        final_decision={"resultHash": "abc", "sample_count": 1},
        confidence_breakdown={"final_confidence": 0.24, "sample_votes": []},
        process_summary={
            "evidence_items_count": 3,
            "failed_tool_calls_count": 0,
            "reanalysis_count": 2,
            "research_stall_streak": 0,
        },
    )
    events = _read_events(logger_rich.log_path)
    fc = events[-1]
    assert fc.confidence_breakdown["final_confidence"] == 0.24
    assert fc.process_summary["reanalysis_count"] == 2
```

Append to `tests/test_agent.py`:

```python
def test_process_summary_from_state_counts_evidence_and_loops():
    from sast_triage.agent import _process_summary_from_state
    from sast_triage.graph.state import (
        CodeEvidence,
        EvidenceBundle,
        ToolCallRecord,
    )

    final_state = {
        "evidence": EvidenceBundle(
            items=[CodeEvidence(file_path="a.py", content="x")]
        ),
        "failed_tool_calls": [ToolCallRecord(tool_name="t", error="boom")],
        "reanalysis_count": 2,
        "research_stall_streak": 1,
    }
    summary = _process_summary_from_state(final_state)
    assert summary == {
        "evidence_items_count": 1,
        "failed_tool_calls_count": 1,
        "reanalysis_count": 2,
        "research_stall_streak": 1,
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .venv/bin/activate && python -m pytest tests/test_session_log_session.py::test_finding_complete_carries_breakdown_and_process_summary tests/test_agent.py::test_process_summary_from_state_counts_evidence_and_loops -v`
Expected: FAIL. The session test fails with `TypeError: emit_finding_complete() got an unexpected keyword argument 'confidence_breakdown'`; the agent test fails with `ImportError: cannot import name '_process_summary_from_state'`.

- [ ] **Step 3: Extend `emit_finding_complete`**

In `sast_triage/session_log/session.py`, replace the signature and event construction (lines 173-198) with:

```python
    def emit_finding_complete(
        self,
        *,
        finding_id: str,
        stop_reason: Optional[str],
        final_decision: Dict[str, Any],
        confidence_breakdown: Optional[Dict[str, Any]] = None,
        process_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        started = self._finding_perf_start.pop(finding_id, time.perf_counter())
        total_duration_ms = (time.perf_counter() - started) * 1000.0
        agg = self._finding_agg
        event = FindingCompleteEvent(
            **self._envelope(),
            finding_id=finding_id,
            stop_reason=stop_reason,
            final_decision=final_decision,
            confidence_breakdown=confidence_breakdown,
            process_summary=process_summary,
            total_duration_ms=total_duration_ms,
            per_node_visit_counts=dict(agg["per_node_visit_counts"]),
            per_node_durations_ms=dict(agg["per_node_durations"]),
            per_node_token_totals={
                node: TokenTotals(**totals)
                for node, totals in agg["per_node_tokens"].items()
            },
            llm_calls_count=agg["llm_calls"],
            tool_calls_count=agg["tool_calls"],
            total_tokens=TokenTotals(**agg["tokens"]),
        )
        self._writer.write(event)
        self._roll_finding_into_session(final_decision)
        self._active_finding_id = None
```

- [ ] **Step 4: Add the agent helper and wire the success path**

In `sast_triage/agent.py`, add `Mapping` to the typing import (line 11):

```python
from typing import Any, Dict, List, Mapping, Optional
```

Add this module-level helper (place it near the top of the module after the imports, before the class definition):

```python
def _process_summary_from_state(final_state: Mapping[str, Any]) -> Dict[str, int]:
    """Final per-finding process counters for the finding_complete event.

    Read from the state dict that ``ainvoke`` returns; the values are the
    real state objects (an ``EvidenceBundle``, a list, two ints).
    """
    evidence = final_state.get("evidence")
    failed = final_state.get("failed_tool_calls") or []
    items = getattr(evidence, "items", []) or []
    return {
        "evidence_items_count": len(items),
        "failed_tool_calls_count": len(failed),
        "reanalysis_count": int(final_state.get("reanalysis_count", 0) or 0),
        "research_stall_streak": int(final_state.get("research_stall_streak", 0) or 0),
    }
```

Then replace the success-path emit block (lines 289-298) with:

```python
            decision = result["verdict"]
            stop_reason = result.get("stop_reason") if isinstance(
                result, dict
            ) else None
            breakdown = (
                result.get("confidence_breakdown")
                if isinstance(result, dict)
                else None
            )

            self.session_logger.emit_finding_complete(
                finding_id=result_hash,
                stop_reason=stop_reason,
                final_decision=decision.model_dump(),
                confidence_breakdown=(
                    breakdown.model_dump() if breakdown is not None else None
                ),
                process_summary=_process_summary_from_state(result),
            )
```

The exception path (lines 319-323) is left unchanged: it calls `emit_finding_complete` without the new arguments, which default to `None`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/test_session_log_session.py tests/test_agent.py -v`
Expected: PASS (old and new).

- [ ] **Step 6: Commit**

```bash
git add sast_triage/session_log/session.py sast_triage/agent.py tests/test_session_log_session.py tests/test_agent.py
git commit -m "feat(agent): log the confidence breakdown and process summary on finding_complete"
```

---

### Task 5: Viewer header card, table fixes and inspector

The viewer has no automated test harness; verify manually against a sample log. All rendering uses the existing safe-DOM helpers (`el`, `dim`, `renderKvTable`, `<details>`); no `innerHTML`, consistent with the CSP.

**Files:**
- Modify: `viewer/viewer.js`
- Modify: `viewer/viewer.css`

- [ ] **Step 1: Add the header-card render functions**

In `viewer/viewer.js`, add these functions just before `renderFlow` (before line 660):

```javascript
  function reanalysisCount(c) {
    if (c.process_summary && c.process_summary.reanalysis_count != null) {
      return c.process_summary.reanalysis_count;
    }
    const visits = c.per_node_visit_counts || {};
    return visits.analyst != null && visits.analyst > 1 ? visits.analyst - 1 : 0;
  }

  function criticTrail(finding) {
    const trail = [];
    for (const ev of finding.events) {
      if (ev.type === "node_exit" && ev.node === "critic" && ev.state_writes) {
        const lc = ev.state_writes.last_critique;
        if (lc) trail.push({ decision: lc.decision || "?", weakest_point: lc.weakest_point || "" });
      }
    }
    if (!trail.length) {
      let prev = null;
      for (const ev of finding.events) {
        if (ev.type === "node_enter" && ev.state_snapshot && ev.state_snapshot.last_critique_decision) {
          const dec = ev.state_snapshot.last_critique_decision;
          if (dec !== prev) {
            trail.push({ decision: dec, weakest_point: "" });
            prev = dec;
          }
        }
      }
    }
    return trail;
  }

  function dispositionReason(d, bd) {
    if (d.is_vulnerable === true) return "Positive verdict → CONFIRMED regardless of confidence.";
    if (d.is_vulnerable == null) return "No majority verdict → REFUSED for manual review.";
    if (bd && bd.final_confidence != null && bd.threshold != null) {
      return bd.final_confidence >= bd.threshold
        ? "Negative at/above threshold " + bd.threshold.toFixed(2) + " → NOT_EXPLOITABLE."
        : "Negative below threshold " + bd.threshold.toFixed(2) + " → PROPOSED_NOT_EXPLOITABLE for human review.";
    }
    return "";
  }

  function renderConfidenceBreakdown(d, bd) {
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Confidence breakdown" })]));
    const body = el("div", { cls: "body" });
    if (!bd) {
      body.appendChild(renderKvTable([
        ["confidence", d.confidence != null ? d.confidence.toFixed(4) : "—"],
        ["agreement_rate", d.agreement_rate != null ? d.agreement_rate : "—"],
        ["sample_count", d.sample_count],
      ]));
      body.appendChild(el("div", { cls: "muted", text: "Detailed breakdown not in this log (pre-v2)." }));
      det.appendChild(body);
      return det;
    }
    const W = bd.agreement_weight;
    const agr = bd.agreement_rate;
    let formula;
    if (d.is_vulnerable == null) {
      // Split or no-majority vote: raw is forced to 0, so the blend does not apply.
      formula = "no majority vote → raw " + bd.raw_confidence.toFixed(2);
    } else {
      const evTerm = (1 - W).toFixed(2) + " x evidence(" + bd.evidence_strength.toFixed(2) + ")";
      formula = agr != null
        ? W.toFixed(2) + " x agreement(" + agr.toFixed(2) + ") + " + evTerm
        : evTerm + " (agreement not credited: single sample)";
      formula += " = " + bd.raw_confidence.toFixed(2) + " raw";
    }
    if (bd.cap_applied) formula += " → capped " + bd.cap_value.toFixed(2);
    formula += " → final " + bd.final_confidence.toFixed(2);
    body.appendChild(el("div", { cls: "fh-formula mono", text: formula }));
    body.appendChild(renderKvTable([
      ["agreement_rate", agr != null ? agr : "—"],
      ["evidence_strength", bd.evidence_strength],
      ["agreement_weight", W],
      ["raw_confidence", bd.raw_confidence],
      ["cap_applied", String(bd.cap_applied)],
      ["cap_value", bd.cap_value],
      ["final_confidence", bd.final_confidence],
      ["threshold", bd.threshold],
    ]));
    const reason = dispositionReason(d, bd);
    if (reason) body.appendChild(el("div", { cls: "muted", text: reason }));
    det.appendChild(body);
    return det;
  }

  function renderSampleVotes(bd) {
    const votes = bd && bd.sample_votes ? bd.sample_votes : null;
    const n = votes ? votes.length : 0;
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Sample votes (" + n + ")" })]));
    const body = el("div", { cls: "body" });
    if (!votes) {
      body.appendChild(el("div", { cls: "muted", text: "Per-sample votes not in this log (pre-v2)." }));
      det.appendChild(body);
      return det;
    }
    const tbl = el("table", { cls: "kv-table fh-votes" });
    tbl.appendChild(el("tr", null, [
      el("td", { cls: "key", text: "vuln" }),
      el("td", { cls: "key", text: "self-conf" }),
      el("td", { cls: "key", text: "temp" }),
      el("td", { cls: "key", text: "cites" }),
      el("td", { cls: "key", text: "evidence" }),
    ]));
    for (const v of votes) {
      tbl.appendChild(el("tr", null, [
        el("td", { cls: "val", text: String(v.is_vulnerable) }),
        el("td", { cls: "val", text: v.self_confidence != null ? v.self_confidence.toFixed(2) : "—" }),
        el("td", { cls: "val", text: v.temperature != null ? v.temperature : "—" }),
        el("td", { cls: "val", text: v.n_citations }),
        el("td", { cls: "val", text: v.n_evidence_refs }),
      ]));
    }
    body.appendChild(tbl);
    det.appendChild(body);
    return det;
  }

  function renderProcessDiagnostics(finding, c) {
    const ps = c.process_summary || null;
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Process diagnostics" })]));
    const body = el("div", { cls: "body" });
    const rows = [];
    if (ps) {
      rows.push(["evidence_items", ps.evidence_items_count]);
      rows.push(["failed_tool_calls", ps.failed_tool_calls_count]);
      rows.push(["reanalysis_count", ps.reanalysis_count]);
      rows.push(["research_stall_streak", ps.research_stall_streak]);
    }
    rows.push(["llm_calls", c.llm_calls_count]);
    rows.push(["tool_calls", c.tool_calls_count]);
    rows.push(["total_tokens", c.total_tokens ? c.total_tokens.total : null]);
    rows.push(["duration", fmtMs(c.total_duration_ms)]);
    body.appendChild(renderKvTable(rows));
    const trail = criticTrail(finding);
    if (trail.length) {
      body.appendChild(el("h4", { text: "Critic trail" }));
      body.appendChild(el("div", { cls: "mono", text: trail.map((t) => t.decision).join(" → ") }));
      const last = trail[trail.length - 1];
      if (last && last.weakest_point) body.appendChild(dim("weakest point: " + last.weakest_point));
    }
    if (!ps) body.appendChild(el("div", { cls: "muted", text: "Process counters not in this log (pre-v2)." }));
    det.appendChild(body);
    return det;
  }

  function renderFindingHeader(finding) {
    const card = el("div", { cls: "finding-header" });
    card.appendChild(el("div", { cls: "fh-title", text: "Finding " + shortenHash(finding.findingId) }));
    const c = finding.completeEvent;
    if (!c) {
      card.appendChild(el("div", { cls: "muted", text: "Finding incomplete (no finding_complete event)." }));
      return card;
    }
    const d = c.final_decision || {};
    const bd = c.confidence_breakdown || null;
    const ps = c.process_summary || null;
    const s = finding.startEvent;

    const parts = [];
    parts.push("conf " + (d.confidence != null ? d.confidence.toFixed(2) : "—"));
    parts.push("vuln=" + String(d.is_vulnerable));
    if (s && s.finding && s.finding.cweID) parts.push("CWE-" + s.finding.cweID);
    if (s && s.checklist_id) parts.push("checklist " + s.checklist_id + " (" + (s.checklist_selection_method || "?") + ")");
    if (c.stop_reason) parts.push("stop " + c.stop_reason);

    const voted = d.sample_count != null ? d.sample_count : findingSampleCount(finding);
    const loops = ps ? ps.reanalysis_count : reanalysisCount(c);
    const attempts = findingSampleCount(finding);
    let countText = voted + " voted";
    if (loops) countText += " · " + loops + " reanalysis loop" + (loops === 1 ? "" : "s");
    if (attempts && attempts !== voted) countText += " · " + attempts + " attempts";
    parts.push(countText);
    parts.push(fmtMs(c.total_duration_ms));
    if (c.total_tokens && c.total_tokens.total) parts.push(fmtTokens(c.total_tokens.total) + " tok");

    const verdict = el("div", { cls: "fh-verdict" }, [
      el("span", { cls: "state-badge state-" + (d.suggested_state || ""), text: d.suggested_state || "—" }),
      document.createTextNode(" "),
      dim(parts.join(" · ")),
    ]);
    card.appendChild(verdict);

    card.appendChild(renderConfidenceBreakdown(d, bd));
    card.appendChild(renderSampleVotes(bd));
    card.appendChild(renderProcessDiagnostics(finding, c));
    return card;
  }
```

- [ ] **Step 2: Wire the header into the finding view**

In `renderFlowAndTimeline` (lines 507-515), change the `if (finding)` branch to render the header before the flow:

```javascript
    if (finding) {
      wrap.appendChild(renderFindingHeader(finding));
      wrap.appendChild(renderFlow(finding));
    } else {
      wrap.appendChild(
        el("div", { cls: "flow-section" }, [
          el("div", { cls: "muted", text: "Select a finding above to see its topology and timeline." }),
        ])
      );
    }
```

- [ ] **Step 3: Fix the findings-table columns**

In `renderFindingsTable`, replace the `samples` and `reanalysis` entries of the `rows.push({...})` object (lines 549 and 551) with truthful logged values:

```javascript
        samples: c ? (decision.sample_count != null ? decision.sample_count : findingSampleCount(f)) : 0,
        research: visits.research || 0,
        reanalysis: c ? reanalysisCount(c) : 0,
```

(The `research` line is unchanged and shown only for placement context.)

- [ ] **Step 4: Reuse the breakdown in the finding_complete inspector**

In `inspectorBody` (line 1077), pass `session` to the finding_complete handler:

```javascript
      case "finding_complete":
        return inspectFindingComplete(ev, session);
```

Then change `inspectFindingComplete` (line 1342) to accept `session` and append the breakdown blocks after the justification. Replace its signature and the block just after the justification line (lines 1342-1354) with:

```javascript
  function inspectFindingComplete(ev, session) {
    const wrap = el("div");
    const d = ev.final_decision || {};
    wrap.appendChild(el("h4", { text: "Verdict" }));
    wrap.appendChild(
      renderKvTable([
        ["resultHash", d.resultHash],
        ["is_vulnerable", String(d.is_vulnerable)],
        ["confidence", d.confidence != null ? d.confidence.toFixed(2) : null],
        ["suggested_state", d.suggested_state],
      ])
    );
    if (d.justification) wrap.appendChild(collapsibleText("Justification", d.justification));
    if (ev.confidence_breakdown || d.confidence != null) {
      wrap.appendChild(renderConfidenceBreakdown(d, ev.confidence_breakdown || null));
    }
    if (ev.confidence_breakdown) wrap.appendChild(renderSampleVotes(ev.confidence_breakdown));
    const finding = session.findings.get(ev.finding_id);
    if (finding) wrap.appendChild(renderProcessDiagnostics(finding, ev));
```

The remainder of `inspectFindingComplete` (the "Totals", "Per-node visits", "Per-node durations", "Per-node tokens" sections and the final `return wrap;`) is unchanged.

- [ ] **Step 5: Add the CSS**

Append to `viewer/viewer.css`:

```css
/* ===== Per-finding header card ===== */
.finding-header {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--c-finding);
  border-radius: 4px;
  padding: 10px 12px;
  margin-bottom: 12px;
}
.finding-header .fh-title {
  font-weight: 600;
  color: var(--c-finding);
  margin-bottom: 6px;
}
.finding-header .fh-verdict {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
}
.finding-header .fh-block {
  margin-top: 4px;
}
.finding-header .fh-formula {
  font-family: var(--font-mono);
  background: var(--accent-soft);
  border-radius: 3px;
  padding: 6px 8px;
  margin-bottom: 8px;
  white-space: pre-wrap;
}
.finding-header .fh-votes td {
  white-space: nowrap;
}
```

- [ ] **Step 6: Manual verification**

Pick a session log that exercises reanalysis, ideally one that hit `max_reanalysis`. If none exists, run the agent once or use a log under `logs/`.

1. Open `viewer/index.html` in a browser.
2. Load a `.jsonl` log via Browse or drag-drop, then click a finding row.
3. Confirm: the header card appears below the table and above the topology; the verdict line shows the state badge, confidence, checklist and "N voted" count; the three blocks expand; the confidence formula matches the kv-table numbers; `cap_applied` is reflected by the "capped" term when a breaker fired.
4. Confirm the table `samples` column now shows the voted count (not the analyst-call count) and `reanalysis` shows the loop count.
5. Click the `finding_complete` timeline row; confirm the inspector shows the same breakdown.
6. Load an older (pre-v2) log; confirm the header falls back with the "not in this log" notes and the table falls back to the old heuristics without errors. Check the browser console for errors (there should be none).

- [ ] **Step 7: Commit**

```bash
git add viewer/viewer.js viewer/viewer.css
git commit -m "feat(viewer): per-finding header card with confidence breakdown"
```

---

### Task 6: Documentation

**Files:**
- Modify: `docs/session-log.md`
- Modify: `docs/session-log-viewer.md`

- [ ] **Step 1: Update the event-schema doc**

In `docs/session-log.md`, in the `finding_complete` row of the per-finding lifecycle table (around line 62), note v2 and the two new fields, and add a short subsection after the event-types tables describing the shapes:

```markdown
`finding_complete` (v2) additionally carries `confidence_breakdown` and
`process_summary` (both optional; absent on v1 logs and on the error path).

- `confidence_breakdown`: the inputs that produced the calibrated confidence:
  `agreement_rate`, `evidence_strength`, `agreement_weight`, `raw_confidence`,
  `cap_applied`, `cap_value`, `final_confidence` (equals
  `final_decision.confidence`), `threshold`, and `sample_votes` (one entry per
  surviving voting sample: `is_vulnerable`, `self_confidence`, `temperature`,
  `n_citations`, `n_evidence_refs`). Structural, so it is identical in rich and
  observability modes.
- `process_summary`: final per-finding counters: `evidence_items_count`,
  `failed_tool_calls_count`, `reanalysis_count`, `research_stall_streak`.
```

Bump the versioning note: `finding_complete` is now at v2; all other types remain at v1.

- [ ] **Step 2: Update the viewer doc**

In `docs/session-log-viewer.md`:

- In the Panes section, add a "Finding header" entry describing the full-width
  card shown when a finding is selected (verdict line plus collapsible
  confidence breakdown, sample votes and process diagnostics), placed below the
  findings table and above the topology.
- In the Findings table description, correct the column semantics: `samples` is
  the voted sample count (`final_decision.sample_count`) and `reanalysis` is the
  logged reanalysis-loop count (`process_summary.reanalysis_count`), with the
  analyst-call count surfaced in the header as "attempts".
- In the Inspector list, note that `finding_complete` renders the confidence
  breakdown and per-sample votes.
- In the Coupling section, add `confidence_breakdown` and `process_summary` on
  `finding_complete` (v2) as fields the viewer reads.

- [ ] **Step 3: Commit**

```bash
git add docs/session-log.md docs/session-log-viewer.md
git commit -m "docs(session-log): document finding_complete v2 and the viewer header"
```

---

## Final verification

- [ ] Run the full Python suite: `source .venv/bin/activate && python -m pytest tests/ -q`
  Expected: all pass.
- [ ] Confirm `git log --oneline` shows the six task commits on `feature/viewer-finding-header`.
