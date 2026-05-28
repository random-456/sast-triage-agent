"""Compile the per-finding triage subgraph.

Nodes are injected rather than imported so this skeleton stands alone: the
real research/analyst/critic/aggregate nodes land in later bricks, and the
cutover wires them in. Tests pass stub nodes to exercise the topology.

When a ``session_logger`` is supplied the three routing functions are
wrapped so each branch choice becomes a ``route_decision`` event; the
wrapped functions remain pure pass-throughs returning the same string the
original returned.
"""

from typing import Callable, Optional

from langgraph.graph import END, StateGraph

from sast_triage.graph.routing import (
    route_after_aggregate,
    route_from_analyst,
    route_from_critic,
)
from sast_triage.graph.state import TriageState

Node = Callable


def build_per_finding_graph(
    *,
    research_node: Node,
    analyst_node: Node,
    critic_node: Node,
    aggregate_node: Node,
    session_logger: Optional[object] = None,
):
    """Build and compile the per-finding `StateGraph`.

    Topology (doc 07):
        research -> analyst -> (critic | research)
        critic -> (research | analyst | aggregate)
        aggregate -> (END | research)

    Args:
        session_logger: optional ``SessionLogger``. When given, routing
            functions are wrapped to emit ``route_decision`` events.
    """
    if session_logger is not None:
        from sast_triage.session_log import wrap_route

        route_analyst = wrap_route(session_logger, route_from_analyst)
        route_critic = wrap_route(session_logger, route_from_critic)
        route_aggregate = wrap_route(session_logger, route_after_aggregate)
    else:
        route_analyst = route_from_analyst
        route_critic = route_from_critic
        route_aggregate = route_after_aggregate

    graph = StateGraph(TriageState)

    graph.add_node("research", research_node)
    graph.add_node("analyst", analyst_node)
    graph.add_node("critic", critic_node)
    graph.add_node("aggregate", aggregate_node)

    graph.set_entry_point("research")
    graph.add_edge("research", "analyst")

    graph.add_conditional_edges(
        "analyst",
        route_analyst,
        {"critic": "critic", "research": "research"},
    )
    graph.add_conditional_edges(
        "critic",
        route_critic,
        {
            "research": "research",
            "analyst": "analyst",
            "aggregate": "aggregate",
        },
    )
    graph.add_conditional_edges(
        "aggregate",
        route_aggregate,
        {"end": END, "research": "research"},
    )

    return graph.compile()
