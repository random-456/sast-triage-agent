"""End-to-end-ish tests for ``SessionLogger``.

Exercise the emit methods directly and check what lands on disk. These
do not run the graph; the integration test does that.
"""

import dataclasses
import json

import pytest
from pydantic import TypeAdapter

from sast_triage.preprocessing.obfuscation import (
    ObfuscationEntry,
    ObfuscationReport,
)
from sast_triage.preprocessing.secret_masking import (
    MaskingEntry,
    MaskingReport,
)
from sast_triage.session_log.events import (
    LogMode,
    SessionLogEvent,
    StateSnapshot,
    UsageMetadata,
)
from sast_triage.session_log.session import SessionLogger


def _read_events(path):
    adapter = TypeAdapter(SessionLogEvent)
    with open(path, "r", encoding="utf-8") as f:
        return [adapter.validate_json(line) for line in f if line.strip()]


@pytest.fixture
def logger_rich(tmp_path):
    log = SessionLogger(tmp_path / "rich.jsonl", log_mode=LogMode.RICH)
    yield log
    log.finalize()


@pytest.fixture
def logger_obs(tmp_path):
    log = SessionLogger(tmp_path / "obs.jsonl", log_mode=LogMode.OBSERVABILITY)
    yield log
    log.finalize()


def _agent_config():
    return {"INITIAL_SAMPLES": 2, "ANALYST_TEMPERATURES": [0.1, 0.3, 0.5]}


def test_session_start_event_is_written(logger_rich, tmp_path):
    logger_rich.emit_session_start(
        model="gemini-2.5-pro",
        agent_config=_agent_config(),
        project_name="p",
        scan_id="s",
    )
    events = _read_events(logger_rich.log_path)
    assert len(events) == 1
    e = events[0]
    assert e.type == "session_start"
    assert e.model == "gemini-2.5-pro"
    assert e.agent_config["INITIAL_SAMPLES"] == 2
    assert e.seq == 1


def test_preprocessing_complete_accepts_asdict_of_preprocessing_dataclasses(
    logger_rich,
):
    """ObfuscationReport and MaskingReport are dataclasses, not Pydantic
    models, so the run_triage entry point feeds dataclasses.asdict output
    to emit_preprocessing_complete. Lock that path down end to end: build
    realistic reports, asdict them, emit, parse back from disk and assert
    the nested entries round-trip.
    """
    obf = ObfuscationReport(
        total_files_processed=17,
        total_files_modified=17,
        total_replacements=65,
        replacements_by_type={"IPV4": 22, "IPV6": 36, "FQDN": 7},
        entries=[
            ObfuscationEntry(
                file="a.py",
                line=10,
                pattern_type="IPV4",
                original="192.168.56.110",
            )
        ],
    )
    msk = MaskingReport(
        csv_path="report.csv",
        total_entries_in_csv=3,
        total_secrets_masked=2,
        files_modified=1,
        entries=[
            MaskingEntry(
                file="b.py",
                start_line=1,
                end_line=1,
                start_column=10,
                end_column=20,
                description="AWS key",
                secret_preview="AKIA***",
            )
        ],
    )
    logger_rich.emit_preprocessing_complete(
        obfuscation_report=dataclasses.asdict(obf),
        masking_report=dataclasses.asdict(msk),
    )
    events = _read_events(logger_rich.log_path)
    assert len(events) == 1
    e = events[0]
    assert e.type == "preprocessing_complete"
    assert e.obfuscation_report["total_replacements"] == 65
    assert e.obfuscation_report["replacements_by_type"]["IPV4"] == 22
    assert e.obfuscation_report["entries"][0]["original"] == "192.168.56.110"
    assert e.masking_report["csv_path"] == "report.csv"
    assert e.masking_report["entries"][0]["secret_preview"] == "AKIA***"


def test_seq_is_strictly_monotonic(logger_rich):
    logger_rich.emit_session_start(
        model="m", agent_config=_agent_config()
    )
    logger_rich.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    events = _read_events(logger_rich.log_path)
    seqs = [e.seq for e in events]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


def test_finding_aggregates_roll_into_finding_complete(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config=_agent_config())
    logger_rich.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    # Two LLM calls with token usage, one tool call
    logger_rich.emit_llm_call(
        run_id=None,
        parent_run_id=None,
        node="research",
        model="m",
        temperature=0.1,
        mode="with_tools",
        structured_schema=None,
        messages_in=[{"type": "system", "content": "x"}],
        response={"generations": [[{"text": "y"}]]},
        usage_metadata=UsageMetadata(
            input_tokens=10, output_tokens=5, total_tokens=15
        ),
        duration_ms=100.0,
    )
    logger_rich.emit_tool_call(
        run_id=None,
        parent_run_id=None,
        node="research",
        tool_name="read_file",
        args={"file_path": "a.py"},
        result={"content": "..."},
        duration_ms=2.0,
    )
    logger_rich.emit_llm_call(
        run_id=None,
        parent_run_id=None,
        node="analyst",
        model="m",
        temperature=0.3,
        mode="structured",
        structured_schema="AnalystVerdict",
        messages_in=[],
        response={},
        usage_metadata=UsageMetadata(
            input_tokens=20, output_tokens=10, total_tokens=30
        ),
        duration_ms=200.0,
    )
    logger_rich.emit_finding_complete(
        finding_id="abc",
        stop_reason="approved",
        final_decision={
            "resultHash": "abc",
            "suggested_state": "CONFIRMED",
        },
    )
    events = _read_events(logger_rich.log_path)
    fc = events[-1]
    assert fc.type == "finding_complete"
    assert fc.llm_calls_count == 2
    assert fc.tool_calls_count == 1
    assert fc.total_tokens.total == 45  # 15 + 30
    assert fc.per_node_token_totals["research"].total == 15
    assert fc.per_node_token_totals["analyst"].total == 30


def test_session_end_summarizes_findings(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config=_agent_config())
    for fid, state in [("a", "CONFIRMED"), ("b", "NOT_EXPLOITABLE"), ("c", "REFUSED")]:
        logger_rich.emit_finding_start(
            finding_id=fid,
            finding={"resultHash": fid},
            checklist_id="generic",
            checklist_selection_method="default",
        )
        logger_rich.emit_finding_complete(
            finding_id=fid,
            stop_reason="approved",
            final_decision={"resultHash": fid, "suggested_state": state},
        )
    logger_rich.emit_session_end()
    events = _read_events(logger_rich.log_path)
    se = events[-1]
    assert se.type == "session_end"
    assert se.total_findings == 3
    assert se.suggested_state_counts == {
        "CONFIRMED": 1,
        "NOT_EXPLOITABLE": 1,
        "REFUSED": 1,
    }
    assert se.refusal_rate == pytest.approx(1 / 3, abs=1e-4)


def test_node_enter_visit_counter_is_per_finding(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config=_agent_config())
    for fid in ("a", "b"):
        logger_rich.emit_finding_start(
            finding_id=fid,
            finding={"resultHash": fid},
            checklist_id="generic",
            checklist_selection_method="default",
        )
        logger_rich.emit_node_enter(
            node="research",
            visit_index=0,
            run_id=None,
            parent_run_id=None,
            state_snapshot=StateSnapshot(),
        )
        logger_rich.emit_finding_complete(
            finding_id=fid,
            stop_reason=None,
            final_decision={"resultHash": fid, "suggested_state": "CONFIRMED"},
        )
    events = _read_events(logger_rich.log_path)
    enters = [e for e in events if e.type == "node_enter"]
    # Both finding's first research visit are recorded.
    assert len(enters) == 2


def test_rich_mode_records_full_messages_and_response(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config=_agent_config())
    logger_rich.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    logger_rich.emit_llm_call(
        run_id=None,
        parent_run_id=None,
        node="research",
        model="m",
        temperature=0.1,
        mode="plain",
        structured_schema=None,
        messages_in=[{"type": "system", "content": "system prompt"}],
        response={"generations": [[{"text": "the response"}]]},
        usage_metadata=None,
        duration_ms=10.0,
    )
    events = _read_events(logger_rich.log_path)
    llm = [e for e in events if e.type == "llm_call"][0]
    assert llm.messages_in == [{"type": "system", "content": "system prompt"}]
    assert llm.response == {"generations": [[{"text": "the response"}]]}
    assert llm.messages_in_hash is None
    assert llm.response_hash is None


def test_observability_mode_redacts_to_hash_and_length(logger_obs):
    logger_obs.emit_session_start(model="m", agent_config=_agent_config())
    logger_obs.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    payload_in = [{"type": "system", "content": "secret stuff"}]
    payload_out = {"generations": [[{"text": "secret response"}]]}
    logger_obs.emit_llm_call(
        run_id=None,
        parent_run_id=None,
        node="research",
        model="m",
        temperature=0.1,
        mode="plain",
        structured_schema=None,
        messages_in=payload_in,
        response=payload_out,
        usage_metadata=None,
        duration_ms=10.0,
    )
    events = _read_events(logger_obs.log_path)
    llm = [e for e in events if e.type == "llm_call"][0]
    assert llm.messages_in is None
    assert llm.response is None
    assert llm.messages_in_hash and len(llm.messages_in_hash) == 16
    assert llm.response_hash and len(llm.response_hash) == 16
    assert llm.messages_in_chars > 0
    assert llm.response_chars > 0
    # The raw content must not appear anywhere in the persisted line.
    raw = logger_obs.log_path.read_text(encoding="utf-8")
    assert "secret stuff" not in raw
    assert "secret response" not in raw


def test_observability_mode_redacts_tool_result(logger_obs):
    logger_obs.emit_session_start(model="m", agent_config=_agent_config())
    logger_obs.emit_finding_start(
        finding_id="abc",
        finding={"resultHash": "abc"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    logger_obs.emit_tool_call(
        run_id=None,
        parent_run_id=None,
        node="research",
        tool_name="read_file",
        args={"file_path": "a.py"},
        result={"content": "very secret code"},
        duration_ms=5.0,
    )
    events = _read_events(logger_obs.log_path)
    tc = [e for e in events if e.type == "tool_call"][0]
    assert tc.result is None
    assert tc.result_hash and len(tc.result_hash) == 16
    assert tc.result_type == "dict"
    raw = logger_obs.log_path.read_text(encoding="utf-8")
    assert "very secret code" not in raw


def test_observability_mode_hash_is_deterministic(tmp_path):
    """Same input produces the same hash, in this run or another."""
    log_a = SessionLogger(tmp_path / "a.jsonl", log_mode=LogMode.OBSERVABILITY)
    log_b = SessionLogger(tmp_path / "b.jsonl", log_mode=LogMode.OBSERVABILITY)
    for lg in (log_a, log_b):
        lg.emit_session_start(model="m", agent_config={})
        lg.emit_finding_start(
            finding_id="abc",
            finding={"resultHash": "abc"},
            checklist_id="generic",
            checklist_selection_method="default",
        )
        lg.emit_llm_call(
            run_id=None,
            parent_run_id=None,
            node="research",
            model="m",
            temperature=0.1,
            mode="plain",
            structured_schema=None,
            messages_in=[{"x": 1}],
            response={"y": 2},
            usage_metadata=None,
            duration_ms=1.0,
        )
        lg.finalize()
    h_a = [
        e.messages_in_hash for e in _read_events(log_a.log_path) if e.type == "llm_call"
    ][0]
    h_b = [
        e.messages_in_hash for e in _read_events(log_b.log_path) if e.type == "llm_call"
    ][0]
    assert h_a == h_b


def test_emit_route_decision_includes_active_finding_id(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config={})
    logger_rich.emit_finding_start(
        finding_id="fid-1",
        finding={"resultHash": "fid-1"},
        checklist_id="generic",
        checklist_selection_method="default",
    )
    logger_rich.emit_route_decision(
        from_node="analyst",
        to_node="critic",
        predicate="samples_non_empty",
        state_inputs={"samples_count": 1},
    )
    events = _read_events(logger_rich.log_path)
    rd = [e for e in events if e.type == "route_decision"][0]
    assert rd.finding_id == "fid-1"
    assert rd.predicate == "samples_non_empty"


def test_attach_to_graph_config_merges_callbacks(logger_rich):
    cfg = logger_rich.attach_to_graph_config({"recursion_limit": 50})
    assert cfg["recursion_limit"] == 50
    callbacks = cfg["callbacks"]
    assert logger_rich.callback_handler in callbacks
    # Idempotent: attaching twice does not duplicate.
    cfg2 = logger_rich.attach_to_graph_config(cfg)
    assert cfg2["callbacks"].count(logger_rich.callback_handler) == 1


def test_finalize_closes_writer(logger_rich):
    logger_rich.emit_session_start(model="m", agent_config={})
    logger_rich.finalize()
    # Subsequent writes through the underlying writer raise.
    with pytest.raises(RuntimeError):
        logger_rich.emit_session_end()
