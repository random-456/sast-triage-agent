"""Tests for the route-decorator hooks in ``sast_triage.session_log``."""

from unittest.mock import MagicMock

import pytest

from sast_triage.agent_models import (
    AnalystVerdict,
    CritiqueDecision,
    CritiqueResult,
)
from sast_triage.graph.routing import (
    route_after_aggregate,
    route_from_analyst,
    route_from_critic,
)
from sast_triage.graph.state import TriageState
from sast_triage.session_log.routing_hooks import wrap_route


def _state(
    *,
    samples=None,
    research_iterations=0,
    reanalysis_count=0,
    last_critique=None,
    verdict=None,
) -> TriageState:
    from sast_triage.agent_models import CheckmarxFinding
    from sast_triage.checklists import select_checklist

    finding = CheckmarxFinding(resultHash="x")
    checklist = select_checklist(None, None)
    return TriageState(
        finding=finding,
        checklist=checklist,
        samples=samples or [],
        research_iterations=research_iterations,
        reanalysis_count=reanalysis_count,
        last_critique=last_critique,
        verdict=verdict,
    )


def _verdict(is_vuln=True) -> AnalystVerdict:
    return AnalystVerdict(
        is_vulnerable=is_vuln,
        confidence=0.9,
        reasoning="r",
        citation_lines=[],
        evidence_refs=[],
    )


def _critique(decision: CritiqueDecision) -> CritiqueResult:
    return CritiqueResult(
        decision=decision,
        rationale="r",
        weakest_point="wp",
    )


def test_wrapped_function_preserves_return_value():
    session = MagicMock()
    state = _state(samples=[_verdict()])
    wrapped = wrap_route(session, route_from_analyst)
    assert wrapped(state) == route_from_analyst(state) == "critic"


def test_route_from_analyst_emits_samples_non_empty():
    session = MagicMock()
    state = _state(samples=[_verdict()])
    wrapped = wrap_route(session, route_from_analyst)
    wrapped(state)
    session.emit_route_decision.assert_called_once()
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["from_node"] == "analyst"
    assert kw["to_node"] == "critic"
    assert kw["predicate"] == "samples_non_empty"
    assert kw["state_inputs"]["samples_count"] == 1


def test_route_from_analyst_emits_samples_empty():
    session = MagicMock()
    state = _state(samples=[])
    wrapped = wrap_route(session, route_from_analyst)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["to_node"] == "research"
    assert kw["predicate"] == "samples_empty"


def test_route_from_critic_predicate_max_research_breaker():
    session = MagicMock()
    state = _state(
        samples=[_verdict()],
        research_iterations=5,
        last_critique=_critique(CritiqueDecision.APPROVED),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["to_node"] == "aggregate"
    assert kw["predicate"] == "max_research_breaker"
    assert kw["state_inputs"]["research_iterations"] == 5


def test_route_from_critic_predicate_max_reanalysis_breaker():
    session = MagicMock()
    state = _state(
        samples=[_verdict()],
        reanalysis_count=2,
        last_critique=_critique(CritiqueDecision.REANALYZE),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["predicate"] == "max_reanalysis_breaker"


def test_route_from_critic_predicate_approved_more_samples_needed():
    session = MagicMock()
    state = _state(
        samples=[_verdict()],
        last_critique=_critique(CritiqueDecision.APPROVED),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["to_node"] == "analyst"
    assert kw["predicate"] == "approved_more_samples_needed"


def test_route_from_critic_predicate_approved_target_reached():
    session = MagicMock()
    state = _state(
        samples=[_verdict(), _verdict()],
        last_critique=_critique(CritiqueDecision.APPROVED),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["to_node"] == "aggregate"
    assert kw["predicate"] == "approved_target_reached"


def test_route_from_critic_predicate_needs_more_research():
    session = MagicMock()
    state = _state(
        samples=[_verdict()],
        last_critique=_critique(CritiqueDecision.NEEDS_MORE_RESEARCH),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["to_node"] == "research"
    assert kw["predicate"] == "needs_more_research"


def test_route_from_critic_predicate_reanalyze():
    session = MagicMock()
    state = _state(
        samples=[_verdict()],
        last_critique=_critique(CritiqueDecision.REANALYZE),
    )
    wrapped = wrap_route(session, route_from_critic)
    wrapped(state)
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["predicate"] == "reanalyze"


def test_route_after_aggregate_predicate_verdict_written():
    from sast_triage.agent_models import SuggestedState, TriageDecision

    session = MagicMock()
    verdict = TriageDecision(
        resultHash="x",
        is_vulnerable=True,
        confidence=0.9,
        suggested_state=SuggestedState.CONFIRMED,
        justification="j",
    )
    state = _state(verdict=verdict)
    wrapped = wrap_route(session, route_after_aggregate)
    assert wrapped(state) == "end"
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["predicate"] == "verdict_written"


def test_route_after_aggregate_predicate_no_verdict_loopback():
    session = MagicMock()
    state = _state(verdict=None)
    wrapped = wrap_route(session, route_after_aggregate)
    assert wrapped(state) == "research"
    kw = session.emit_route_decision.call_args.kwargs
    assert kw["predicate"] == "no_verdict_loopback"


def test_wrap_route_unknown_function_passes_through(caplog):
    session = MagicMock()

    def custom_route(state):
        return "somewhere"

    wrapped = wrap_route(session, custom_route)
    assert wrapped is custom_route
    session.emit_route_decision.assert_not_called()


def test_emit_failure_does_not_break_routing(caplog):
    """If the session logger errors, the routing decision still returns."""
    session = MagicMock()
    session.emit_route_decision.side_effect = RuntimeError("boom")
    state = _state(samples=[_verdict()])
    wrapped = wrap_route(session, route_from_analyst)
    assert wrapped(state) == "critic"
