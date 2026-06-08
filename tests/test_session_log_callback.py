"""Tests for ``TriageLoggingCallback``."""

import uuid
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, LLMResult

from sast_triage.session_log.callback import TriageLoggingCallback


@pytest.fixture
def session():
    return MagicMock()


@pytest.fixture
def handler(session):
    return TriageLoggingCallback(session)


def _ai_with_usage(content="ok", usage=None, tool_calls=None):
    msg = AIMessage(content=content)
    if usage is not None:
        msg.usage_metadata = usage
    if tool_calls is not None:
        msg.tool_calls = tool_calls
    return msg


def _llm_result(message):
    gen = ChatGeneration(message=message, text=getattr(message, "content", "") or "")
    return LLMResult(generations=[[gen]])


async def test_on_chat_model_start_then_end_emits_llm_call(handler, session):
    run_id = uuid.uuid4()
    parent_id = uuid.uuid4()
    messages = [
        [
            SystemMessage(content="sys"),
            HumanMessage(content="hi"),
        ]
    ]
    serialized = {"kwargs": {"model_name": "gemini-2.5-pro", "temperature": 0.1}}

    await handler.on_chat_model_start(
        serialized,
        messages,
        run_id=run_id,
        parent_run_id=parent_id,
        tags=["session_log:mode=structured", "session_log:schema=AnalystVerdict"],
    )
    ai = _ai_with_usage(
        usage={"input_tokens": 5, "output_tokens": 7, "total_tokens": 12}
    )
    await handler.on_llm_end(_llm_result(ai), run_id=run_id, parent_run_id=parent_id)

    session.emit_llm_call.assert_called_once()
    kw = session.emit_llm_call.call_args.kwargs
    assert kw["model"] == "gemini-2.5-pro"
    assert kw["temperature"] == 0.1
    assert kw["mode"] == "structured"
    assert kw["structured_schema"] == "AnalystVerdict"
    assert kw["usage_metadata"].total_tokens == 12
    assert len(kw["messages_in"]) == 2
    assert kw["response"] is not None


async def test_on_llm_end_without_start_is_ignored(handler, session):
    """Unpaired end (probably from a different callback handler) -- no emit."""
    run_id = uuid.uuid4()
    await handler.on_llm_end(
        _llm_result(_ai_with_usage()), run_id=run_id, parent_run_id=None
    )
    session.emit_llm_call.assert_not_called()


async def test_default_mode_is_plain(handler, session):
    run_id = uuid.uuid4()
    await handler.on_chat_model_start(
        {"kwargs": {}}, [[]], run_id=run_id, parent_run_id=None, tags=None
    )
    await handler.on_llm_end(
        _llm_result(_ai_with_usage()), run_id=run_id, parent_run_id=None
    )
    kw = session.emit_llm_call.call_args.kwargs
    assert kw["mode"] == "plain"
    assert kw["structured_schema"] is None


async def test_mode_with_tools_tag(handler, session):
    run_id = uuid.uuid4()
    await handler.on_chat_model_start(
        {"kwargs": {}},
        [[]],
        run_id=run_id,
        parent_run_id=None,
        tags=["session_log:mode=with_tools"],
    )
    await handler.on_llm_end(
        _llm_result(_ai_with_usage()), run_id=run_id, parent_run_id=None
    )
    assert session.emit_llm_call.call_args.kwargs["mode"] == "with_tools"


async def test_on_llm_error_emits_error_event_and_clears_start(handler, session):
    run_id = uuid.uuid4()
    await handler.on_chat_model_start(
        {"kwargs": {}}, [[]], run_id=run_id, parent_run_id=None, tags=None
    )
    await handler.on_llm_error(
        ValueError("boom"), run_id=run_id, parent_run_id=None
    )
    session.emit_error.assert_called_once()
    kw = session.emit_error.call_args.kwargs
    assert kw["scope"] == "llm"
    assert kw["error_type"] == "ValueError"
    # The successful pair should no longer fire after error
    await handler.on_llm_end(
        _llm_result(_ai_with_usage()), run_id=run_id, parent_run_id=None
    )
    session.emit_llm_call.assert_not_called()


async def test_on_chain_start_for_node_emits_node_enter(handler, session):
    run_id = uuid.uuid4()
    inputs = {
        "evidence": {"items": []},
        "failed_tool_calls": [],
        "samples": [],
        "research_iterations": 0,
        "reanalysis_count": 0,
        "last_critique": None,
    }
    await handler.on_chain_start(
        {"name": "research"},
        inputs,
        run_id=run_id,
        parent_run_id=None,
        tags=None,
        metadata=None,
    )
    session.emit_node_enter.assert_called_once()
    kw = session.emit_node_enter.call_args.kwargs
    assert kw["node"] == "research"
    assert kw["visit_index"] == 0
    assert kw["state_snapshot"].evidence_items_count == 0


async def test_on_chain_start_for_non_node_does_not_emit(handler, session):
    run_id = uuid.uuid4()
    await handler.on_chain_start(
        {"name": "some_internal_chain"},
        {},
        run_id=run_id,
        parent_run_id=None,
    )
    session.emit_node_enter.assert_not_called()


async def test_node_visit_index_increments_per_node(handler, session):
    for _ in range(3):
        await handler.on_chain_start(
            {"name": "research"},
            {},
            run_id=uuid.uuid4(),
            parent_run_id=None,
        )
    visits = [call.kwargs["visit_index"] for call in session.emit_node_enter.call_args_list]
    assert visits == [0, 1, 2]


async def test_on_chain_end_emits_node_exit_with_duration(handler, session):
    run_id = uuid.uuid4()
    await handler.on_chain_start(
        {"name": "analyst"},
        {},
        run_id=run_id,
        parent_run_id=None,
    )
    await handler.on_chain_end({"samples": [1, 2]}, run_id=run_id, parent_run_id=None)
    session.emit_node_exit.assert_called_once()
    kw = session.emit_node_exit.call_args.kwargs
    assert kw["node"] == "analyst"
    assert kw["state_writes"] == {"samples": [1, 2]}
    assert kw["duration_ms"] >= 0.0


async def test_on_tool_start_then_end_emits_tool_call(handler, session):
    run_id = uuid.uuid4()
    parent_id = uuid.uuid4()
    await handler.on_tool_start(
        {"name": "read_file"},
        '{"file_path": "x.py"}',
        run_id=run_id,
        parent_run_id=parent_id,
        inputs={"file_path": "x.py"},
    )
    await handler.on_tool_end(
        {"content": "..."}, run_id=run_id, parent_run_id=parent_id
    )
    session.emit_tool_call.assert_called_once()
    kw = session.emit_tool_call.call_args.kwargs
    assert kw["tool_name"] == "read_file"
    assert kw["args"] == {"file_path": "x.py"}
    assert kw["result"] == {"content": "..."}


async def test_on_tool_error_emits_error(handler, session):
    run_id = uuid.uuid4()
    await handler.on_tool_start(
        {"name": "read_file"},
        "{}",
        run_id=run_id,
        parent_run_id=None,
        inputs={"file_path": "missing"},
    )
    await handler.on_tool_error(
        FileNotFoundError("nope"), run_id=run_id, parent_run_id=None
    )
    kw = session.emit_error.call_args.kwargs
    assert kw["scope"] == "tool"


async def test_llm_attributed_to_parent_node(handler, session):
    """LLM call's parent_run_id matches an active node visit."""
    node_run_id = uuid.uuid4()
    await handler.on_chain_start(
        {"name": "analyst"},
        {},
        run_id=node_run_id,
        parent_run_id=None,
    )
    llm_run_id = uuid.uuid4()
    await handler.on_chat_model_start(
        {"kwargs": {}}, [[]], run_id=llm_run_id, parent_run_id=node_run_id, tags=None
    )
    await handler.on_llm_end(
        _llm_result(_ai_with_usage()), run_id=llm_run_id, parent_run_id=node_run_id
    )
    kw = session.emit_llm_call.call_args.kwargs
    assert kw["node"] == "analyst"


async def test_reset_for_finding_clears_visit_counts_and_pending(handler, session):
    await handler.on_chain_start(
        {"name": "research"},
        {},
        run_id=uuid.uuid4(),
        parent_run_id=None,
    )
    handler.reset_for_finding()
    await handler.on_chain_start(
        {"name": "research"},
        {},
        run_id=uuid.uuid4(),
        parent_run_id=None,
    )
    visits = [call.kwargs["visit_index"] for call in session.emit_node_enter.call_args_list]
    # After reset, the next visit_index starts at 0 again.
    assert visits[-1] == 0


async def test_code_bank_summary_only_for_analyst_and_critic(handler, session):
    state = {
        "evidence": {
            "items": [
                {
                    "file_path": "a.py",
                    "relevance": "read_file",
                    "content": "x" * 100,
                }
            ]
        },
    }
    await handler.on_chain_start(
        {"name": "research"},
        state,
        run_id=uuid.uuid4(),
        parent_run_id=None,
    )
    assert (
        session.emit_node_enter.call_args.kwargs["state_snapshot"].code_bank_summary
        is None
    )
    await handler.on_chain_start(
        {"name": "analyst"},
        state,
        run_id=uuid.uuid4(),
        parent_run_id=None,
    )
    snap = session.emit_node_enter.call_args.kwargs["state_snapshot"]
    assert snap.code_bank_summary is not None
    assert snap.code_bank_summary[0]["content_chars"] == 100
