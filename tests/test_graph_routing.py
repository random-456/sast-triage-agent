"""Tests for per-finding graph routing and compiled topology.

Routing functions are tested directly with synthetic state. The compiled
graph is exercised with sync stub nodes (no LLM) to verify the topology and
circuit breakers wire together.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    DEFAULT_SAMPLES,
    INITIAL_SAMPLES,
    MAX_REANALYSIS_LOOPS,
    MAX_RESEARCH_ITERATIONS,
)
from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueDecision,
    CritiqueResult,
    TriageDecision,
)
from sast_triage.checklists import load_checklist
from sast_triage.graph.build import build_per_finding_graph
from sast_triage.graph.routing import (
    compute_stop_reason,
    route_after_aggregate,
    route_from_analyst,
    route_from_critic,
    target_samples_for,
)
from sast_triage.graph.state import TriageState


def _state(**overrides) -> TriageState:
    base = dict(
        finding=CheckmarxFinding(resultHash="h", cweID="89"),
        checklist=load_checklist("sqli"),
    )
    base.update(overrides)
    return TriageState(**base)


def _verdict() -> AnalystVerdict:
    return AnalystVerdict(is_vulnerable=True, confidence=0.9, reasoning="r")


def _critique(decision: CritiqueDecision) -> CritiqueResult:
    return CritiqueResult(
        decision=decision, rationale="x", weakest_point="y"
    )


class TestRouteFromAnalyst:
    def test_with_sample_goes_to_critic(self):
        assert route_from_analyst(_state(samples=[_verdict()])) == "critic"

    def test_without_sample_goes_back_to_research(self):
        assert route_from_analyst(_state(samples=[])) == "research"


class TestRouteFromCritic:
    def test_approved_with_room_collects_another_sample(self):
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        assert route_from_critic(state) == "analyst"

    def test_approved_at_target_aggregates(self):
        state = _state(
            samples=[_verdict()] * DEFAULT_SAMPLES,
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        assert route_from_critic(state) == "aggregate"

    def test_needs_more_research_routes_to_research(self):
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(CritiqueDecision.NEEDS_MORE_RESEARCH),
        )
        assert route_from_critic(state) == "research"

    def test_reanalyze_routes_to_analyst(self):
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(CritiqueDecision.REANALYZE),
        )
        assert route_from_critic(state) == "analyst"

    def test_research_breaker_overrides_a_continue_decision(self):
        # Even an APPROVED-needs-more verdict aggregates once research is maxed.
        state = _state(
            samples=[_verdict()],
            research_iterations=MAX_RESEARCH_ITERATIONS,
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        assert route_from_critic(state) == "aggregate"

    def test_reanalysis_breaker_aggregates(self):
        state = _state(
            samples=[_verdict()],
            reanalysis_count=MAX_REANALYSIS_LOOPS,
            last_critique=_critique(CritiqueDecision.REANALYZE),
        )
        assert route_from_critic(state) == "aggregate"

    def test_missing_critique_aggregates(self):
        assert route_from_critic(_state(samples=[_verdict()])) == "aggregate"


class TestRouteAfterAggregate:
    def test_no_verdict_loops_to_research(self):
        assert route_after_aggregate(_state()) == "research"

    def test_verdict_ends(self):
        decision = TriageDecision(
            resultHash="h",
            is_vulnerable=True,
            confidence=0.9,
            suggested_state="CONFIRMED",
            justification="j",
        )
        assert route_after_aggregate(_state(verdict=decision)) == "end"


def _no_vote() -> AnalystVerdict:
    return AnalystVerdict(is_vulnerable=False, confidence=0.9, reasoning="r")


class TestTargetSamplesFor:
    def test_below_initial_targets_initial(self):
        assert target_samples_for(_state(samples=[])) == INITIAL_SAMPLES
        assert target_samples_for(_state(samples=[_verdict()])) == INITIAL_SAMPLES

    def test_majority_at_initial_stops_there(self):
        state = _state(samples=[_verdict(), _verdict()])
        assert target_samples_for(state) == INITIAL_SAMPLES

    def test_split_at_initial_adds_a_tiebreaker(self):
        state = _state(samples=[_verdict(), _no_vote()])
        assert target_samples_for(state) == DEFAULT_SAMPLES

    def test_caps_at_default_samples(self):
        state = _state(
            samples=[
                _verdict(),
                _no_vote(),
                AnalystVerdict(is_vulnerable=None, confidence=0.0, reasoning="r"),
            ]
        )
        assert target_samples_for(state) == DEFAULT_SAMPLES


class TestComputeStopReason:
    def test_research_breaker(self):
        state = _state(research_iterations=MAX_RESEARCH_ITERATIONS)
        assert compute_stop_reason(state) == "max_research"

    def test_reanalysis_breaker(self):
        state = _state(reanalysis_count=MAX_REANALYSIS_LOOPS)
        assert compute_stop_reason(state) == "max_reanalysis"

    def test_approved(self):
        state = _state(last_critique=_critique(CritiqueDecision.APPROVED))
        assert compute_stop_reason(state) == "approved"

    def test_none_when_no_terminal_condition(self):
        state = _state(last_critique=_critique(CritiqueDecision.REANALYZE))
        assert compute_stop_reason(state) is None


def _final_verdict() -> TriageDecision:
    return TriageDecision(
        resultHash="h",
        is_vulnerable=True,
        confidence=0.9,
        suggested_state="CONFIRMED",
        justification="j",
    )


def _stub_research(state):
    return {"research_iterations": state.research_iterations + 1}


def _stub_analyst(state):
    return {"samples": state.samples + [_verdict()]}


def _stub_aggregate(state):
    return {"verdict": _final_verdict(), "stop_reason": compute_stop_reason(state)}


def _build(critic):
    return build_per_finding_graph(
        research_node=_stub_research,
        analyst_node=_stub_analyst,
        critic_node=critic,
        aggregate_node=_stub_aggregate,
    )


def _initial():
    return {
        "finding": CheckmarxFinding(resultHash="h", cweID="89"),
        "checklist": load_checklist("sqli"),
    }


class TestCompiledTopology:
    """The compiled graph runs end to end with stub nodes, no LLM."""

    def test_approved_path_collects_samples_then_aggregates(self):
        graph = _build(
            lambda s: {"last_critique": _critique(CritiqueDecision.APPROVED)}
        )
        result = graph.invoke(_initial())
        assert result["stop_reason"] == "approved"
        assert result["verdict"] is not None
        # Agreeing samples reach a majority at INITIAL_SAMPLES, so adaptive
        # sampling stops there rather than collecting the full ceiling.
        assert len(result["samples"]) == INITIAL_SAMPLES
        # Entry research runs once; APPROVED resampling loops analyst<->critic.
        assert result["research_iterations"] == 1

    def test_persistent_needs_more_research_trips_the_breaker(self):
        graph = _build(
            lambda s: {
                "last_critique": _critique(
                    CritiqueDecision.NEEDS_MORE_RESEARCH
                )
            }
        )
        result = graph.invoke(_initial())
        assert result["stop_reason"] == "max_research"
        assert result["research_iterations"] == MAX_RESEARCH_ITERATIONS
        assert result["verdict"] is not None
