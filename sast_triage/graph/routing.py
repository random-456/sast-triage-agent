"""Routing logic for the per-finding triage subgraph.

These functions are pure reads over `TriageState`: they pick the next node
and never mutate state. Counter increments (research_iterations,
reanalysis_count) and `stop_reason`/`verdict` writes belong to the nodes, so
the routing decision and the recorded outcome stay consistent.
"""

from typing import Optional

from config import (
    DEFAULT_SAMPLES,
    MAX_REANALYSIS_LOOPS,
    MAX_RESEARCH_ITERATIONS,
)
from sast_triage.agent_models import CritiqueDecision
from sast_triage.graph.state import StopReason, TriageState


def target_samples_for(state: TriageState) -> int:
    """How many self-consistency samples this finding should collect.

    Fixed at `DEFAULT_SAMPLES` for now; PR5 replaces this with the adaptive
    sampling from doc 05 (start at 2, add a tiebreaker on disagreement).
    """
    return DEFAULT_SAMPLES


def route_from_analyst(state: TriageState) -> str:
    """After the analyst runs: critique a produced sample, else research more.

    A missing sample means the analyst could not commit to a verdict, so the
    finding needs more evidence before another attempt.
    """
    return "critic" if state.samples else "research"


def route_from_critic(state: TriageState) -> str:
    """The core branch: research again, reanalyze, or aggregate.

    Circuit breakers are checked first so a runaway loop always terminates at
    the aggregator with a recorded stop reason.
    """
    if state.research_iterations >= MAX_RESEARCH_ITERATIONS:
        return "aggregate"
    if state.reanalysis_count >= MAX_REANALYSIS_LOOPS:
        return "aggregate"

    critique = state.last_critique
    if critique is None:
        # No critique to act on; nothing more we can safely do.
        return "aggregate"

    if critique.decision == CritiqueDecision.APPROVED:
        if len(state.samples) < target_samples_for(state):
            return "analyst"
        return "aggregate"
    if critique.decision == CritiqueDecision.NEEDS_MORE_RESEARCH:
        return "research"
    if critique.decision == CritiqueDecision.REANALYZE:
        return "analyst"
    return "aggregate"


def route_after_aggregate(state: TriageState) -> str:
    """End once a verdict exists; otherwise the tiebreak path researches more."""
    return "end" if state.verdict is not None else "research"


def compute_stop_reason(state: TriageState) -> Optional[StopReason]:
    """Why the subgraph reached the aggregator, mirroring `route_from_critic`.

    Breaker-first ordering matches the router so the recorded reason agrees
    with the branch that was actually taken.
    """
    if state.research_iterations >= MAX_RESEARCH_ITERATIONS:
        return "max_research"
    if state.reanalysis_count >= MAX_REANALYSIS_LOOPS:
        return "max_reanalysis"
    if (
        state.last_critique is not None
        and state.last_critique.decision == CritiqueDecision.APPROVED
    ):
        return "approved"
    return None
