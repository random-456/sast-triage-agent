"""Integration test: the real aggregate node inside the compiled graph."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import INITIAL_SAMPLES
from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    ConfidenceBreakdown,
    CritiqueDecision,
    CritiqueResult,
    SuggestedState,
    TriageDecision,
)
from sast_triage.checklists import load_checklist
from sast_triage.graph.aggregate import aggregate_node
from sast_triage.graph.build import build_per_finding_graph


def _research(state):
    return {"research_iterations": state.research_iterations + 1}


def _analyst(state):
    verdict = AnalystVerdict(
        is_vulnerable=True,
        confidence=0.9,
        reasoning="tainted value reaches the sink",
        citation_lines=["Dao.java:10"],
        evidence_refs=["Dao.java"],
    )
    return {"samples": state.samples + [verdict]}


def _critic(state):
    return {
        "last_critique": CritiqueResult(
            decision=CritiqueDecision.APPROVED,
            rationale="defensible",
            weakest_point="none",
        )
    }


async def test_real_aggregate_node_produces_decision_in_graph():
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
    verdict = result["verdict"]
    assert isinstance(verdict, TriageDecision)
    assert verdict.is_vulnerable is True
    assert verdict.suggested_state == SuggestedState.CONFIRMED
    assert verdict.agreement_rate == 1.0
    assert verdict.sample_count == INITIAL_SAMPLES
    assert result["stop_reason"] == "approved"


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
