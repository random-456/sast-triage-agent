"""Tests for the adversarial critic node."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from langchain_core.messages import HumanMessage

from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueDecision,
    CritiqueResult,
)
from sast_triage.checklists import load_checklist
from sast_triage.graph.critic import build_critic_messages, make_critic_node
from sast_triage.graph.state import CodeEvidence, TriageState


class _FakeLLM:
    def __init__(self, result):
        self.result = result
        self.captured = []

    async def ainvoke(self, messages):
        self.captured.append(messages)
        return self.result


def _state(**overrides) -> TriageState:
    base = dict(
        finding=CheckmarxFinding(resultHash="h", cweID="89"),
        checklist=load_checklist("sqli"),
    )
    base.update(overrides)
    return TriageState(**base)


def _verdict(reasoning="because of the concat") -> AnalystVerdict:
    return AnalystVerdict(
        is_vulnerable=True, confidence=0.8, reasoning=reasoning
    )


class TestCriticNode:
    async def test_returns_last_critique(self):
        critique = CritiqueResult(
            decision=CritiqueDecision.REANALYZE,
            rationale="reachability not shown",
            weakest_point="no taint to the sink",
        )
        node = make_critic_node(_FakeLLM(critique))
        result = await node(_state(samples=[_verdict()]))
        assert result["last_critique"] is critique
        assert result["last_critique"].decision == CritiqueDecision.REANALYZE


class TestCriticMessages:
    def test_includes_checklist_codebank_and_verdict(self):
        state = _state(samples=[_verdict()])
        state.evidence.add(
            CodeEvidence(
                file_path="Dao.java", content="stmt.execute(q)", relevance="read_file"
            )
        )
        messages = build_critic_messages(state)
        joined = "\n".join(str(m.content) for m in messages)
        assert "SQL Injection (CWE-89)" in joined  # checklist
        assert "stmt.execute(q)" in joined  # code bank evidence
        assert "because of the concat" in joined  # the verdict reasoning
        assert isinstance(messages[-1], HumanMessage)
