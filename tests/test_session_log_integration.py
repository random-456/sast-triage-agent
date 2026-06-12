"""Graph-level integration: build a real per-finding graph with the
session logger attached, run it with stub nodes (no real LLM), and check
that the JSONL event stream is well-formed and complete enough for a
viewer to reconstruct the run.
"""

from pydantic import TypeAdapter

from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueDecision,
    CritiqueResult,
)
from sast_triage.checklists import load_checklist
from sast_triage.graph.aggregate import aggregate_node
from sast_triage.graph.build import build_per_finding_graph
from sast_triage.session_log.events import SessionLogEvent
from sast_triage.session_log.session import SessionLogger


def _research(state):
    return {"research_iterations": state.research_iterations + 1}


def _analyst(state):
    verdict = AnalystVerdict(
        is_vulnerable=True,
        confidence=0.9,
        reasoning="r",
        citation_lines=["a.py:1"],
        evidence_refs=["a.py"],
    )
    return {"samples": state.samples + [verdict]}


def _critic(state):
    return {
        "last_critique": CritiqueResult(
            decision=CritiqueDecision.APPROVED,
            rationale="r",
            weakest_point="wp",
        )
    }


async def test_full_graph_emits_well_ordered_event_stream(tmp_path):
    log_path = tmp_path / "session.jsonl"
    session = SessionLogger(log_path)
    session.emit_session_start(models={"research": "m", "analyst": "m", "critic": "m"}, agent_config={"INITIAL_SAMPLES": 2})

    graph = build_per_finding_graph(
        research_node=_research,
        analyst_node=_analyst,
        critic_node=_critic,
        aggregate_node=aggregate_node,
        session_logger=session,
    )

    finding = CheckmarxFinding(resultHash="abc", cweID="89")
    checklist = load_checklist("sqli")
    session.emit_finding_start(
        finding_id="abc",
        finding=finding.model_dump(),
        checklist_id=checklist.checklist_id,
        checklist_selection_method="cwe",
    )
    session.emit_graph_invoke_start(finding_id="abc", recursion_limit=50)
    invoke_config = session.attach_to_graph_config({"recursion_limit": 50})
    result = await graph.ainvoke(
        {"finding": finding, "checklist": checklist},
        config=invoke_config,
    )
    session.emit_graph_invoke_end(finding_id="abc")
    session.emit_finding_complete(
        finding_id="abc",
        stop_reason=result.get("stop_reason"),
        final_decision=result["verdict"].model_dump(),
    )
    session.emit_session_end()
    session.finalize()

    adapter = TypeAdapter(SessionLogEvent)
    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            events.append(adapter.validate_json(line))

    types = [e.type for e in events]
    seqs = [e.seq for e in events]

    # Required envelope: monotonic seq, one session_id, all carry timestamps.
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)
    sids = {e.session_id for e in events}
    assert len(sids) == 1
    assert all(e.ts for e in events)

    # Skeleton must contain the per-finding lifecycle.
    assert "session_start" in types
    assert "finding_start" in types
    assert "graph_invoke_start" in types
    assert "node_enter" in types
    assert "node_exit" in types
    assert "route_decision" in types
    assert "graph_invoke_end" in types
    assert "finding_complete" in types
    assert "session_end" in types
    # No errors.
    assert "error" not in types

    # Per-node enter/exit pairs balance.
    enters = [e for e in events if e.type == "node_enter"]
    exits = [e for e in events if e.type == "node_exit"]
    assert len(enters) == len(exits)
    for entered, exited in zip(enters, exits, strict=False):
        assert entered.node == exited.node

    # Visited nodes match the topology (research -> analyst -> critic -> aggregate).
    visited_nodes = [e.node for e in enters]
    assert visited_nodes[0] == "research"
    assert "analyst" in visited_nodes
    assert visited_nodes[-1] == "aggregate"

    # finding_complete carries the aggregated final decision and counters.
    fc = next(e for e in events if e.type == "finding_complete")
    assert fc.final_decision["is_vulnerable"] is True
    assert fc.llm_calls_count == 0  # no LLM in this stub run
    assert fc.tool_calls_count == 0

    # session_end summarizes one finding.
    se = next(e for e in events if e.type == "session_end")
    assert se.total_findings == 1
    assert se.suggested_state_counts.get("CONFIRMED") == 1


async def test_routing_events_carry_predicate_and_state_inputs(tmp_path):
    """Each routing function emits a route_decision with the right predicate."""
    log_path = tmp_path / "session.jsonl"
    session = SessionLogger(log_path)
    session.emit_session_start(models={"research": "m", "analyst": "m", "critic": "m"}, agent_config={})

    graph = build_per_finding_graph(
        research_node=_research,
        analyst_node=_analyst,
        critic_node=_critic,
        aggregate_node=aggregate_node,
        session_logger=session,
    )
    finding = CheckmarxFinding(resultHash="abc", cweID="89")
    checklist = load_checklist("sqli")
    session.emit_finding_start(
        finding_id="abc",
        finding=finding.model_dump(),
        checklist_id=checklist.checklist_id,
        checklist_selection_method="cwe",
    )
    session.emit_graph_invoke_start(finding_id="abc", recursion_limit=50)
    invoke_config = session.attach_to_graph_config({"recursion_limit": 50})
    result = await graph.ainvoke(
        {"finding": finding, "checklist": checklist},
        config=invoke_config,
    )
    session.emit_graph_invoke_end(finding_id="abc")
    session.emit_finding_complete(
        finding_id="abc",
        stop_reason=result.get("stop_reason"),
        final_decision=result["verdict"].model_dump(),
    )
    session.finalize()

    adapter = TypeAdapter(SessionLogEvent)
    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            events.append(adapter.validate_json(line))

    routes = [e for e in events if e.type == "route_decision"]
    by_from = {r.from_node: r for r in routes}

    # The graph visits the three pure routing functions: analyst, critic, aggregate.
    assert "analyst" in by_from
    assert "critic" in by_from
    assert "aggregate" in by_from
    # analyst -> critic because a sample is produced.
    assert by_from["analyst"].to_node == "critic"
    assert by_from["analyst"].predicate == "samples_non_empty"
    # critic -> aggregate (approved + samples target reached on the second pass).
    assert by_from["critic"].to_node == "aggregate"
    # aggregate -> end after a verdict is written.
    assert by_from["aggregate"].to_node == "end"
    assert by_from["aggregate"].predicate == "verdict_written"
