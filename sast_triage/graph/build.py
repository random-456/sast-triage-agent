"""Compile the per-finding triage subgraph.

Nodes are injected rather than imported so this skeleton stands alone: the
real research/analyst/critic/aggregate nodes land in later bricks, and the
cutover wires them in. Tests pass stub nodes to exercise the topology.
"""

from typing import Callable

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
):
    """Build and compile the per-finding `StateGraph`.

    Topology (doc 07):
        research -> analyst -> (critic | research)
        critic -> (research | analyst | aggregate)
        aggregate -> (END | research)
    """
    graph = StateGraph(TriageState)

    graph.add_node("research", research_node)
    graph.add_node("analyst", analyst_node)
    graph.add_node("critic", critic_node)
    graph.add_node("aggregate", aggregate_node)

    graph.set_entry_point("research")
    graph.add_edge("research", "analyst")

    graph.add_conditional_edges(
        "analyst",
        route_from_analyst,
        {"critic": "critic", "research": "research"},
    )
    graph.add_conditional_edges(
        "critic",
        route_from_critic,
        {
            "research": "research",
            "analyst": "analyst",
            "aggregate": "aggregate",
        },
    )
    graph.add_conditional_edges(
        "aggregate",
        route_after_aggregate,
        {"end": END, "research": "research"},
    )

    return graph.compile()
