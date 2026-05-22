"""Tests for the stateless research node.

A fake LLM captures the messages it receives each turn so we can assert the
stateless property (per-turn input does not grow with iteration count) and
that failed tool calls are fed back into the next turn's prompt.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import MAX_TOOL_CALLS_PER_RESEARCH
from sast_triage.agent_models import CheckmarxFinding
from sast_triage.checklists import load_checklist
from sast_triage.graph.research import (
    build_research_system_prompt,
    format_code_bank,
    make_research_node,
)
from sast_triage.graph.state import CodeEvidence, ToolCallRecord, TriageState


class _Response:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class _FakeLLM:
    """Returns scripted responses, falling back to a default once exhausted."""

    def __init__(self, scripted, default=None):
        self.scripted = list(scripted)
        self.default = default
        self.calls = []  # the message list passed on each ainvoke

    async def ainvoke(self, messages):
        self.calls.append(messages)
        if self.scripted:
            return self.scripted.pop(0)
        return self.default


class _FakeTool:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def invoke(self, args):
        return self._fn(args)


def _read_ok(args):
    return {"file": args["file_path"], "content": ["1: code"]}


def _read_err(args):
    return {"error": "File not found"}


def _call(name, args, call_id):
    return {"name": name, "args": args, "id": call_id}


def _state(**overrides) -> TriageState:
    base = dict(
        finding=CheckmarxFinding(resultHash="h", cweID="89", queryName="SQL_Injection"),
        checklist=load_checklist("sqli"),
    )
    base.update(overrides)
    return TriageState(**base)


def _read_tool():
    return _FakeTool("read_file", _read_ok)


class TestPromptBuilders:
    def test_code_bank_empty(self):
        assert "No evidence gathered yet" in format_code_bank(_state())

    def test_code_bank_renders_items(self):
        state = _state()
        state.evidence.add(
            CodeEvidence(file_path="a.java", content="x=1", relevance="read_file")
        )
        rendered = format_code_bank(state)
        assert "a.java" in rendered
        assert "x=1" in rendered

    def test_system_prompt_includes_finding_and_checklist(self):
        prompt = build_research_system_prompt(_state())
        assert "h" in prompt  # resultHash
        assert "SQL Injection (CWE-89)" in prompt

    def test_system_prompt_surfaces_failed_calls(self):
        state = _state(
            failed_tool_calls=[
                ToolCallRecord(
                    tool_name="read_file",
                    arguments={"file_path": "x"},
                    error="File not found",
                )
            ]
        )
        prompt = build_research_system_prompt(state)
        assert "DO NOT RETRY" in prompt
        assert "read_file" in prompt


class TestResearchNode:
    async def test_ends_on_response_with_no_tool_calls(self):
        llm = _FakeLLM([_Response(content="done")])
        node = make_research_node(llm, [_read_tool()])
        result = await node(_state())
        assert len(llm.calls) == 1
        assert result["evidence"].items == []
        assert result["research_iterations"] == 1

    async def test_increments_research_iterations(self):
        llm = _FakeLLM([_Response(content="done")])
        node = make_research_node(llm, [_read_tool()])
        result = await node(_state(research_iterations=2))
        assert result["research_iterations"] == 3

    async def test_successful_tool_call_accumulates_evidence(self):
        llm = _FakeLLM(
            [
                _Response(tool_calls=[_call("read_file", {"file_path": "a.java"}, "1")]),
                _Response(content="done"),
            ]
        )
        node = make_research_node(llm, [_read_tool()])
        result = await node(_state())
        items = result["evidence"].items
        assert len(items) == 1
        assert items[0].file_path == "a.java"
        assert items[0].relevance == "read_file"

    async def test_per_turn_message_count_is_bounded_not_cumulative(self):
        # Three tool-call turns then a stop. The stateless rebuild means each
        # turn after the first sees the same small message list, never growing.
        llm = _FakeLLM(
            [
                _Response(tool_calls=[_call("read_file", {"file_path": "a"}, "1")]),
                _Response(tool_calls=[_call("read_file", {"file_path": "b"}, "2")]),
                _Response(tool_calls=[_call("read_file", {"file_path": "c"}, "3")]),
                _Response(content="done"),
            ]
        )
        node = make_research_node(llm, [_read_tool()])
        await node(_state())
        lengths = [len(c) for c in llm.calls]
        # turn 0: system + code bank (no prior round) = 2
        assert lengths[0] == 2
        # later turns: system + code bank + one AI + one ToolMessage = 4
        assert lengths[1] == 4
        assert lengths[2] == 4
        assert lengths[3] == 4
        assert max(lengths) <= 4

    async def test_failed_call_recorded_and_fed_into_next_prompt(self):
        llm = _FakeLLM(
            [
                _Response(tool_calls=[_call("read_file", {"file_path": "x"}, "1")]),
                _Response(content="giving up"),
            ]
        )
        node = make_research_node(llm, [_FakeTool("read_file", _read_err)])
        result = await node(_state())

        records = result["failed_tool_calls"]
        assert len(records) == 1
        assert records[0].tool_name == "read_file"
        assert result["evidence"].items == []
        # The second turn's system prompt must warn against retrying.
        second_turn_system = llm.calls[1][0].content
        assert "DO NOT RETRY" in second_turn_system

    async def test_unknown_tool_is_recorded_as_failure(self):
        llm = _FakeLLM(
            [
                _Response(tool_calls=[_call("nonexistent", {}, "1")]),
                _Response(content="done"),
            ]
        )
        node = make_research_node(llm, [_read_tool()])
        result = await node(_state())
        assert len(result["failed_tool_calls"]) == 1
        assert "not found" in result["failed_tool_calls"][0].error

    async def test_loop_stops_at_tool_call_cap(self):
        # LLM never stops asking for tools; the cap must end the node.
        looping = _Response(tool_calls=[_call("read_file", {"file_path": "a"}, "1")])
        llm = _FakeLLM([], default=looping)
        node = make_research_node(llm, [_read_tool()])
        result = await node(_state())
        assert len(llm.calls) == MAX_TOOL_CALLS_PER_RESEARCH
        assert result["research_iterations"] == 1
