"""Callback-propagation regression test.

Production bug: on Python 3.10 + Windows asyncio (ProactorEventLoop), the
contextvar that LangChain uses to propagate the parent RunnableConfig
(and therefore the callbacks list) into nested LLM and tool calls was
not visible inside graph nodes. As a result, the SessionLogger callback
handler never received on_chat_model_start / on_llm_end / on_tool_start
/ on_tool_end, and the JSONL log was missing all llm_call and tool_call
events.

This test pins the contract that fixes the bug: the real research,
analyst and critic nodes must pass their ``config`` argument explicitly
into every LLM and tool call. With that wiring, the SessionLogger
callback handler sees the LLM and tool events regardless of platform,
without depending on contextvar propagation.
"""

from typing import Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.output_parsers.openai_tools import PydanticToolsParser
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from pydantic import TypeAdapter

from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueDecision,
    CritiqueResult,
)
from sast_triage.checklists import load_checklist
from sast_triage.graph.aggregate import aggregate_node
from sast_triage.graph.analyst import make_analyst_node
from sast_triage.graph.build import build_per_finding_graph
from sast_triage.graph.critic import make_critic_node
from sast_triage.graph.research import make_research_node
from sast_triage.session_log.events import SessionLogEvent
from sast_triage.session_log.session import SessionLogger


@tool
def read_file_tool(file_path: str) -> str:
    """Stub read_file tool."""
    return f"contents of {file_path}"


class _StubChat(BaseChatModel):
    """Minimal BaseChatModel that mimics ChatVertexAI's callback shape.

    The framework wraps ``_agenerate`` with the callback dispatch, so if
    the parent's RunnableConfig is propagated to ``ainvoke``, callbacks
    fire automatically.
    """

    return_tool_call: bool = False
    structured: Any = None

    @property
    def _llm_type(self) -> str:
        return "stub"

    def bind_tools(self, tools, **kwargs):
        return self.bind(tools=tools)

    def with_structured_output(self, schema, **kwargs):
        """Mimic langchain's structured-output: bind the schema as a tool
        and pipe through PydanticToolsParser so the result is a parsed
        Pydantic instance. Callbacks fire on the chat-model step.
        """
        clone = self.model_copy(update={"structured": schema})
        return clone.bind_tools([schema]) | PydanticToolsParser(
            tools=[schema], first_tool_only=True
        )

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.structured is AnalystVerdict:
            verdict = AnalystVerdict(
                is_vulnerable=True,
                confidence=0.9,
                reasoning="stub",
                citation_lines=["a.py:1"],
                evidence_refs=["a.py"],
            )
            msg = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "AnalystVerdict",
                        "args": verdict.model_dump(),
                        "id": "v1",
                    }
                ],
            )
        elif self.structured is CritiqueResult:
            critique = CritiqueResult(
                decision=CritiqueDecision.APPROVED,
                rationale="stub", weakest_point="stub",
            )
            msg = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "CritiqueResult",
                        "args": critique.model_dump(),
                        "id": "c1",
                    }
                ],
            )
        elif self.return_tool_call:
            msg = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "read_file_tool",
                        "args": {"file_path": "a.py"},
                        "id": "t1",
                    }
                ],
                usage_metadata={
                    "input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                },
            )
            # Only one tool call per LLM turn; clear the flag so the
            # next turn ends the loop.
            object.__setattr__(self, "return_tool_call", False)
        else:
            msg = AIMessage(
                content="done",
                usage_metadata={
                    "input_tokens": 20, "output_tokens": 10, "total_tokens": 30,
                },
            )
        return ChatResult(generations=[ChatGeneration(message=msg)])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._generate(messages, stop, run_manager, **kwargs)


def _read_events(path):
    adapter = TypeAdapter(SessionLogEvent)
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(adapter.validate_json(line))
    return out


async def test_real_nodes_propagate_callbacks_to_llm_and_tool_calls(tmp_path):
    """The real research/analyst/critic nodes must propagate the
    parent's RunnableConfig to every LLM and tool call so the
    SessionLogger callback handler emits llm_call and tool_call events.
    """
    log_path = tmp_path / "session.jsonl"
    session = SessionLogger(log_path)
    session.emit_session_start(models={"research": "stub", "analyst": "stub", "critic": "stub"}, agent_config={"INITIAL_SAMPLES": 2})

    research_chat = _StubChat(return_tool_call=True)
    research_llm = (
        research_chat.bind_tools([read_file_tool])
        .with_config({"tags": ["session_log:mode=with_tools"]})
    )

    def analyst_llm_for(_temperature):
        return _StubChat().with_structured_output(AnalystVerdict).with_config(
            {
                "tags": [
                    "session_log:mode=structured",
                    "session_log:schema=AnalystVerdict",
                ]
            }
        )

    critic_llm = (
        _StubChat()
        .with_structured_output(CritiqueResult)
        .with_config(
            {
                "tags": [
                    "session_log:mode=structured",
                    "session_log:schema=CritiqueResult",
                ]
            }
        )
    )

    graph = build_per_finding_graph(
        research_node=make_research_node(research_llm, [read_file_tool]),
        analyst_node=make_analyst_node(analyst_llm_for),
        critic_node=make_critic_node(critic_llm),
        aggregate_node=aggregate_node,
        session_logger=session,
    )

    finding = CheckmarxFinding(resultHash="testhash", cweID="89")
    checklist = load_checklist("sqli")

    session.emit_finding_start(
        finding_id=finding.resultHash,
        finding=finding.model_dump(),
        checklist_id=checklist.checklist_id,
        checklist_selection_method="cwe",
    )
    session.emit_graph_invoke_start(
        finding_id=finding.resultHash, recursion_limit=50
    )
    config = session.attach_to_graph_config({"recursion_limit": 50})
    result = await graph.ainvoke(
        {"finding": finding, "checklist": checklist}, config=config
    )
    session.emit_graph_invoke_end(finding_id=finding.resultHash)
    session.emit_finding_complete(
        finding_id=finding.resultHash,
        stop_reason=result.get("stop_reason"),
        final_decision=result["verdict"].model_dump(),
    )
    session.finalize()

    events = _read_events(log_path)
    llm_calls = [e for e in events if e.type == "llm_call"]
    tool_calls = [e for e in events if e.type == "tool_call"]

    # The bug we are guarding against produced zero llm_call and zero
    # tool_call events. Any positive count proves the wiring is intact.
    assert len(llm_calls) > 0, (
        "no llm_call events were emitted; the SessionLogger callback handler "
        "did not see on_chat_model_start. The nodes are not propagating the "
        "parent's RunnableConfig to the LLM call."
    )
    assert len(tool_calls) > 0, (
        "no tool_call events were emitted; the SessionLogger callback handler "
        "did not see on_tool_start. The research node is not propagating the "
        "parent's RunnableConfig to the tool invocation."
    )

    # Each llm_call must be attributed to the node it ran in (analyst,
    # critic or research), proving the parent-chain walk to find the
    # node ancestor works.
    nodes_with_llm = {e.node for e in llm_calls}
    assert "research" in nodes_with_llm
    assert "analyst" in nodes_with_llm

    # Tool calls happen inside research; check at least one is attributed.
    assert any(e.node == "research" for e in tool_calls)
