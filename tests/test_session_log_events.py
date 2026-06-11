"""Tests for the session-log event Pydantic models.

Covers: discriminated-union parsing, required-field enforcement, and
JSONL round-trip (model -> json -> model produces an equal model).
"""

import json

import pytest
from pydantic import TypeAdapter, ValidationError

from sast_triage.session_log.events import (
    ErrorEvent,
    FindingCompleteEvent,
    FindingStartEvent,
    GraphInvokeEndEvent,
    GraphInvokeStartEvent,
    LLMCallEvent,
    LogMode,
    NodeEnterEvent,
    NodeExitEvent,
    PreprocessingCompleteEvent,
    RouteDecisionEvent,
    SessionEndEvent,
    SessionLogEvent,
    SessionStartEvent,
    StateSnapshot,
    TokenTotals,
    ToolCallEvent,
    UsageMetadata,
)


@pytest.fixture
def envelope():
    return {
        "ts": "2026-05-28T12:00:00.000000+00:00",
        "seq": 1,
        "session_id": "test-session",
    }


def _roundtrip(event):
    adapter = TypeAdapter(SessionLogEvent)
    parsed = adapter.validate_json(event.model_dump_json())
    assert parsed == event


def test_session_start_minimal_required_fields_roundtrip(envelope):
    event = SessionStartEvent(
        **envelope,
        model="gemini-2.5-pro",
        agent_config={"INITIAL_SAMPLES": 2},
        log_mode=LogMode.RICH,
        started_at="2026-05-28T12:00:00.000000+00:00",
    )
    _roundtrip(event)


def test_finding_start_requires_checklist_selection_method(envelope):
    with pytest.raises(ValidationError):
        FindingStartEvent(
            **envelope,
            finding_id="abc",
            finding={"resultHash": "abc"},
            checklist_id="sqli",
            checklist_selection_method="unknown_method",  # type: ignore[arg-type]
        )


def test_node_enter_carries_state_snapshot(envelope):
    snap = StateSnapshot(
        evidence_items_count=3,
        samples_count=1,
        last_critique_decision="APPROVED",
        code_bank_summary=[
            {"file_path": "a.py", "relevance": "read_file", "content_chars": 42}
        ],
    )
    event = NodeEnterEvent(
        **envelope,
        finding_id="abc",
        node="analyst",
        visit_index=0,
        state_snapshot=snap,
    )
    _roundtrip(event)


def test_node_exit_preserves_state_writes(envelope):
    event = NodeExitEvent(
        **envelope,
        finding_id="abc",
        node="research",
        visit_index=0,
        duration_ms=12.34,
        state_writes={"evidence": {"items": []}, "research_iterations": 1},
    )
    _roundtrip(event)


def test_llm_call_rich_mode_carries_messages_and_response(envelope):
    event = LLMCallEvent(
        **envelope,
        model="gemini-2.5-pro",
        mode="structured",
        structured_schema="AnalystVerdict",
        messages_in=[{"type": "system", "content": "x"}],
        response={"generations": [[{"text": "y"}]]},
        usage_metadata=UsageMetadata(
            input_tokens=10, output_tokens=20, total_tokens=30
        ),
        duration_ms=200.0,
    )
    _roundtrip(event)
    assert event.usage_metadata.total_tokens == 30


def test_llm_call_observability_mode_uses_hash_fields(envelope):
    event = LLMCallEvent(
        **envelope,
        model="gemini-2.5-pro",
        mode="with_tools",
        messages_in_hash="abcd1234",
        messages_in_chars=42,
        response_hash="ef567890",
        response_chars=18,
        duration_ms=200.0,
    )
    _roundtrip(event)
    assert event.messages_in is None
    assert event.response is None


def test_tool_call_roundtrip(envelope):
    event = ToolCallEvent(
        **envelope,
        tool_name="read_file",
        args={"file_path": "a.py"},
        result={"content": "..."},
        duration_ms=5.0,
    )
    _roundtrip(event)


def test_route_decision_carries_predicate_and_inputs(envelope):
    event = RouteDecisionEvent(
        **envelope,
        from_node="critic",
        to_node="analyst",
        predicate="approved_more_samples_needed",
        state_inputs={"samples_count": 1, "research_iterations": 2},
    )
    _roundtrip(event)


def test_error_event_requires_scope(envelope):
    with pytest.raises(ValidationError):
        ErrorEvent(
            **envelope,
            scope="filesystem",  # type: ignore[arg-type]
            error_type="OSError",
            error_message="disk full",
        )


def test_graph_invoke_events_roundtrip(envelope):
    start = GraphInvokeStartEvent(
        **envelope, finding_id="abc", recursion_limit=50
    )
    _roundtrip(start)
    end = GraphInvokeEndEvent(
        **envelope, finding_id="abc", duration_ms=123.4
    )
    _roundtrip(end)


def test_preprocessing_complete_allows_missing_reports(envelope):
    event = PreprocessingCompleteEvent(**envelope)
    _roundtrip(event)


def test_finding_complete_aggregates_default_to_empty(envelope):
    event = FindingCompleteEvent(
        **envelope,
        finding_id="abc",
        stop_reason="approved",
        final_decision={"resultHash": "abc"},
        total_duration_ms=1000.0,
    )
    _roundtrip(event)
    assert event.total_tokens.total == 0
    assert event.per_node_visit_counts == {}


def test_session_end_computes_no_default_refusal_rate(envelope):
    event = SessionEndEvent(
        **envelope,
        ended_at="2026-05-28T13:00:00.000000+00:00",
        total_duration_ms=600000.0,
        total_findings=0,
    )
    _roundtrip(event)
    assert event.refusal_rate == 0.0


def test_discriminated_union_dispatch_by_type(envelope):
    """Two different event-type JSON lines parse to the correct concrete model."""
    adapter = TypeAdapter(SessionLogEvent)
    s_line = (
        '{"type":"session_start","v":1,'
        '"ts":"2026-05-28T12:00:00.000000+00:00","seq":1,'
        '"session_id":"x","model":"m","agent_config":{},'
        '"log_mode":"rich","started_at":"2026-05-28T12:00:00.000000+00:00"}'
    )
    parsed_s = adapter.validate_json(s_line)
    assert isinstance(parsed_s, SessionStartEvent)

    r_line = json.dumps(
        {
            "type": "route_decision",
            "v": 1,
            "ts": "2026-05-28T12:00:00.000000+00:00",
            "seq": 2,
            "session_id": "x",
            "from_node": "analyst",
            "to_node": "critic",
            "predicate": "samples_non_empty",
            "state_inputs": {"samples_count": 1},
        }
    )
    parsed_r = adapter.validate_json(r_line)
    assert isinstance(parsed_r, RouteDecisionEvent)


def test_token_totals_default():
    t = TokenTotals()
    assert t.input == 0
    assert t.output == 0
    assert t.total == 0


def test_finding_complete_v2_carries_breakdown_and_summary(envelope):
    event = FindingCompleteEvent(
        **envelope,
        finding_id="abc",
        stop_reason="max_reanalysis",
        final_decision={"resultHash": "abc", "sample_count": 1},
        total_duration_ms=1000.0,
        confidence_breakdown={"final_confidence": 0.24, "sample_votes": []},
        process_summary={
            "evidence_items_count": 3,
            "failed_tool_calls_count": 0,
            "reanalysis_count": 2,
            "research_stall_streak": 0,
        },
    )
    assert event.v == 2
    _roundtrip(event)


def test_finding_complete_without_optional_fields_defaults_to_none(envelope):
    # A log line that omits the optional fields must still parse.
    event = FindingCompleteEvent(
        **envelope,
        finding_id="abc",
        stop_reason="approved",
        final_decision={"resultHash": "abc"},
        total_duration_ms=1000.0,
    )
    assert event.confidence_breakdown is None
    assert event.process_summary is None
    _roundtrip(event)
