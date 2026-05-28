"""Decorators that wrap the per-finding routing functions so each branch
choice becomes a ``route_decision`` event.

LangGraph's conditional edges do not surface as callback events, so we
hook the pure routing functions directly. The decorators do not modify
the original return value, they only emit a side-effect event. The
predicate strings mirror the precedence in
``sast_triage/graph/routing.py``; if that file's logic changes both must
be updated in lockstep.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from config import MAX_REANALYSIS_LOOPS, MAX_RESEARCH_ITERATIONS
from sast_triage.agent_models import CritiqueDecision

logger = logging.getLogger(__name__)


def _critique_decision(state: Any) -> Optional[str]:
    critique = getattr(state, "last_critique", None)
    if critique is None:
        return None
    decision = getattr(critique, "decision", None)
    if decision is None:
        return None
    return decision.value if hasattr(decision, "value") else str(decision)


def _route_from_analyst_inputs(state: Any) -> Dict[str, Any]:
    return {"samples_count": len(getattr(state, "samples", []) or [])}


def _route_from_analyst_predicate(state: Any, to_node: str) -> str:
    return "samples_non_empty" if to_node == "critic" else "samples_empty"


def _route_from_critic_inputs(state: Any) -> Dict[str, Any]:
    return {
        "samples_count": len(getattr(state, "samples", []) or []),
        "research_iterations": getattr(state, "research_iterations", 0),
        "reanalysis_count": getattr(state, "reanalysis_count", 0),
        "last_critique_decision": _critique_decision(state),
    }


def _route_from_critic_predicate(state: Any, to_node: str) -> str:
    if getattr(state, "research_iterations", 0) >= MAX_RESEARCH_ITERATIONS:
        return "max_research_breaker"
    if getattr(state, "reanalysis_count", 0) >= MAX_REANALYSIS_LOOPS:
        return "max_reanalysis_breaker"
    if getattr(state, "last_critique", None) is None:
        return "no_critique"
    decision = _critique_decision(state)
    if decision == CritiqueDecision.APPROVED.value:
        return (
            "approved_target_reached"
            if to_node == "aggregate"
            else "approved_more_samples_needed"
        )
    if decision == CritiqueDecision.NEEDS_MORE_RESEARCH.value:
        return "needs_more_research"
    if decision == CritiqueDecision.REANALYZE.value:
        return "reanalyze"
    return "unknown"


def _route_after_aggregate_inputs(state: Any) -> Dict[str, Any]:
    return {"verdict_present": getattr(state, "verdict", None) is not None}


def _route_after_aggregate_predicate(state: Any, to_node: str) -> str:
    return "verdict_written" if to_node == "end" else "no_verdict_loopback"


_FROM_NODE = {
    "route_from_analyst": "analyst",
    "route_from_critic": "critic",
    "route_after_aggregate": "aggregate",
}

_PREDICATE_FNS = {
    "route_from_analyst": _route_from_analyst_predicate,
    "route_from_critic": _route_from_critic_predicate,
    "route_after_aggregate": _route_after_aggregate_predicate,
}

_INPUTS_FNS = {
    "route_from_analyst": _route_from_analyst_inputs,
    "route_from_critic": _route_from_critic_inputs,
    "route_after_aggregate": _route_after_aggregate_inputs,
}


def wrap_route(session_logger, route_fn):
    """Return a wrapper around ``route_fn`` that emits a route_decision.

    The wrapper is a pass-through: it calls the original function, emits
    one event with the derived predicate and the original return value,
    then returns that value unchanged. ``route_fn`` is identified by its
    ``__name__`` to look up the predicate / inputs / from_node tables.
    """
    name = route_fn.__name__
    from_node = _FROM_NODE.get(name)
    predicate_fn = _PREDICATE_FNS.get(name)
    inputs_fn = _INPUTS_FNS.get(name)

    if from_node is None or predicate_fn is None or inputs_fn is None:
        # Unknown routing function: don't fail the graph, just pass through.
        logger.warning(
            "wrap_route called with unrecognized function %s; passing through",
            name,
        )
        return route_fn

    def wrapped(state):
        to_node = route_fn(state)
        try:
            predicate = predicate_fn(state, to_node)
            state_inputs = inputs_fn(state)
            session_logger.emit_route_decision(
                from_node=from_node,
                to_node=to_node,
                predicate=predicate,
                state_inputs=state_inputs,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("route_decision emit failed: %s", exc)
        return to_node

    wrapped.__name__ = name
    wrapped.__wrapped__ = route_fn
    return wrapped
