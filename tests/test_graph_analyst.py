"""Tests for the analyst node: sampling, refinement and temperature."""

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
from sast_triage.graph.analyst import build_analyst_messages, make_analyst_node
from sast_triage.graph.state import TriageState


class _FakeStructLLM:
    def __init__(self, result, captured):
        self._result = result
        self._captured = captured

    async def ainvoke(self, messages, config=None, **kwargs):
        self._captured.append(messages)
        return self._result.model_copy()


class _AnalystFactory:
    def __init__(self, result=None):
        self.result = result or AnalystVerdict(
            is_vulnerable=True, confidence=0.8, reasoning="r"
        )
        self.temps = []
        self.messages = []

    def __call__(self, temperature):
        self.temps.append(temperature)
        return _FakeStructLLM(self.result, self.messages)


def _verdict(reasoning="r") -> AnalystVerdict:
    return AnalystVerdict(is_vulnerable=True, confidence=0.8, reasoning=reasoning)


def _critique(decision, **kw) -> CritiqueResult:
    return CritiqueResult(
        decision=decision, rationale="x", weakest_point="y", **kw
    )


def _state(**overrides) -> TriageState:
    base = dict(
        finding=CheckmarxFinding(resultHash="h", cweID="89"),
        checklist=load_checklist("sqli"),
    )
    base.update(overrides)
    return TriageState(**base)


class TestSampling:
    async def test_first_run_appends_at_first_temperature(self):
        factory = _AnalystFactory()
        node = make_analyst_node(factory)
        result = await node(_state(), {})
        assert len(result["samples"]) == 1
        assert factory.temps == [0.1]
        assert result["samples"][0].sample_temperature == 0.1
        assert result["current_sample_idx"] == 0

    async def test_fresh_sample_after_approval_uses_next_temperature(self):
        factory = _AnalystFactory()
        node = make_analyst_node(factory)
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        result = await node(state, {})
        assert len(result["samples"]) == 2
        assert factory.temps == [0.3]
        assert result["current_sample_idx"] == 1

    async def test_temperature_clamps_beyond_configured_list(self):
        factory = _AnalystFactory()
        node = make_analyst_node(factory)
        state = _state(
            samples=[_verdict()] * 5,
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        await node(state, {})
        assert factory.temps == [0.5]  # min(5, len-1) -> last entry


class TestRefinement:
    async def test_reanalyze_replaces_last_sample_and_counts(self):
        factory = _AnalystFactory(result=_verdict(reasoning="refined"))
        node = make_analyst_node(factory)
        state = _state(
            samples=[_verdict(reasoning="original")],
            last_critique=_critique(CritiqueDecision.REANALYZE),
            reanalysis_count=0,
        )
        result = await node(state, {})
        assert len(result["samples"]) == 1
        assert result["samples"][0].reasoning == "refined"
        assert result["reanalysis_count"] == 1
        assert factory.temps == [0.1]  # same slot, not advanced

    async def test_needs_more_research_replaces_without_counting(self):
        factory = _AnalystFactory(result=_verdict(reasoning="refined"))
        node = make_analyst_node(factory)
        state = _state(
            samples=[_verdict(reasoning="original")],
            last_critique=_critique(CritiqueDecision.NEEDS_MORE_RESEARCH),
            reanalysis_count=0,
        )
        result = await node(state, {})
        assert len(result["samples"]) == 1
        assert result["samples"][0].reasoning == "refined"
        assert result["reanalysis_count"] == 0


class TestAnalystMessages:
    def test_reanalysis_feedback_is_appended(self):
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(
                CritiqueDecision.REANALYZE,
                reanalysis_feedback="you missed the decoder",
            ),
        )
        messages = build_analyst_messages(state)
        assert isinstance(messages[-1], HumanMessage)
        assert "you missed the decoder" in messages[-1].content

    def test_required_information_is_framed_as_request_not_gathered(self):
        # The critic's required_information must not become a claim that the
        # evidence was obtained: that is false when research could not find it
        # (for example backend code outside the cloned repo) and makes the
        # analyst reason from evidence it does not actually have.
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(
                CritiqueDecision.NEEDS_MORE_RESEARCH,
                required_information=["the backend /rest/track-order source"],
            ),
        )
        refinement = build_analyst_messages(state)[-1].content
        assert "gathered" not in refinement.lower()
        assert "the backend /rest/track-order source" in refinement
        assert "asked" in refinement.lower() or "request" in refinement.lower()

    def test_no_feedback_message_on_fresh_sample(self):
        state = _state(
            samples=[_verdict()],
            last_critique=_critique(CritiqueDecision.APPROVED),
        )
        messages = build_analyst_messages(state)
        # The code bank itself is now a HumanMessage; what must NOT be
        # appended on a fresh sample is a critic-feedback HumanMessage.
        assert not any(
            isinstance(m, HumanMessage) and "reviewer rejected" in m.content
            for m in messages
        )

    def test_request_always_has_at_least_one_non_system_turn(self):
        # Gemini rejects requests whose ``contents`` array is empty
        # ("contents are required"). A fresh sample with no critic feedback
        # must still include at least one HumanMessage so the request is
        # accepted by the API.
        state = _state()
        messages = build_analyst_messages(state)
        assert any(isinstance(m, HumanMessage) for m in messages)

    def test_system_prompt_includes_cwe_checklist(self):
        # The analyst's step 4 references "the CWE-specific checklist below";
        # the rendered checklist must actually be in the system message. The
        # fixture loads the SQLi checklist; verify its display name and the
        # block markers produced by render_checklist_section show up.
        state = _state()
        messages = build_analyst_messages(state)
        system_text = messages[0].content
        assert "SQL Injection (CWE-89)" in system_text
        assert "REQUIRED EVIDENCE" in system_text
        assert "EFFECTIVE CONTROLS" in system_text
        assert "INEFFECTIVE / BYPASSABLE" in system_text
