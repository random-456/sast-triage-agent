"""
Test suite for AgentLoggingManager logging improvements.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.agent_logging import (
    AgentLoggingManager,
    _compact_tool_result,
    _hash_prompt,
    _strip_signatures,
)
from sast_triage.agent_models import TriageDecision


@dataclass
class FakeObfuscationReport:
    """Minimal stand-in for ObfuscationReport."""

    total_files_processed: int = 10
    total_files_modified: int = 3
    total_replacements: int = 25
    replacements_by_type: dict = field(
        default_factory=lambda: {"ip_address": 15, "hostname": 10}
    )


@dataclass
class FakeMaskingReport:
    """Minimal stand-in for MaskingReport."""

    csv_path: str = "gitleaks.csv"
    total_entries_in_csv: int = 50
    total_secrets_masked: int = 12
    files_modified: int = 5
    skipped_entries: list = field(
        default_factory=lambda: [{"reason": "not found"}]
    )


class TestSessionMetadata:
    """Tests for session metadata in log (7a)."""

    def test_session_metadata_in_log(self, tmp_path):
        """Verify log contains project_name, branch, etc."""
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            project_name="my-project",
            project_id="proj-123",
            scan_id="scan-456",
            repo_url="https://git.example.com/repo.git",
            branch="main",
        )
        mgr.log_file = tmp_path / "test_log.json"
        mgr.save_log()

        with open(mgr.log_file) as f:
            log = json.load(f)

        meta = log["session_metadata"]
        assert meta["model"] == "gemini-2.5-pro"
        assert meta["temperature"] == 0.1
        assert meta["project_name"] == "my-project"
        assert meta["project_id"] == "proj-123"
        assert meta["scan_id"] == "scan-456"
        assert meta["repo_url"] == "https://git.example.com/repo.git"
        assert meta["branch"] == "main"

    def test_session_metadata_defaults_to_none(self, tmp_path):
        """Verify optional metadata fields default to None."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"
        mgr.save_log()

        with open(mgr.log_file) as f:
            log = json.load(f)

        meta = log["session_metadata"]
        assert meta["project_name"] is None
        assert meta["project_id"] is None
        assert meta["scan_id"] is None
        assert meta["repo_url"] is None
        assert meta["branch"] is None

    def test_log_structure_has_expected_keys(self, tmp_path):
        """Verify top-level log structure has all expected keys."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"
        mgr.save_log()

        with open(mgr.log_file) as f:
            log = json.load(f)

        expected_keys = {
            "session_start",
            "session_metadata",
            "preprocessing",
            "findings_processed",
            "session_summary",
        }
        assert set(log.keys()) == expected_keys


class TestTokenUsage:
    """Tests for per-finding token usage tracking (7b)."""

    def test_token_usage_recorded(self, tmp_path):
        """Verify token usage is accumulated in finding log."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        finding_log = mgr.log_finding_start("hash-001")

        mgr.log_token_usage(
            finding_log,
            {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        )
        mgr.log_token_usage(
            finding_log,
            {"input_tokens": 200, "output_tokens": 80, "total_tokens": 280},
        )

        assert finding_log["token_usage"]["input"] == 300
        assert finding_log["token_usage"]["output"] == 130
        assert finding_log["token_usage"]["total"] == 430

    def test_token_usage_defaults_to_zero(self, tmp_path):
        """Verify finding log starts with zero token usage."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        finding_log = mgr.log_finding_start("hash-002")

        assert finding_log["token_usage"] == {
            "input": 0,
            "output": 0,
            "total": 0,
        }

    def test_token_usage_handles_missing_keys(self, tmp_path):
        """Verify partial token metadata doesn't crash."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        finding_log = mgr.log_finding_start("hash-003")
        mgr.log_token_usage(finding_log, {"input_tokens": 50})

        assert finding_log["token_usage"]["input"] == 50
        assert finding_log["token_usage"]["output"] == 0
        assert finding_log["token_usage"]["total"] == 0


class TestOutputFilenameTimestamp:
    """Tests for timestamp in output filename (7c)."""

    def test_output_filename_has_timestamp(self):
        """Verify filename includes date/time pattern."""
        with patch("sast_triage.agent.ChatVertexAI") as mock_chat:
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_chat.return_value = mock_llm

            from sast_triage.agent import SASTTriageAgent

            agent = SASTTriageAgent(
                project="test-project",
                location="test-location",
                model_name="test-model",
                project_name="myproject",
            )

        filename = Path(agent.assessments_file).name
        pattern = r"findings_assessment_myproject_\d{8}_\d{6}\.json"
        assert re.match(pattern, filename), (
            f"Filename '{filename}' does not match expected "
            f"timestamp pattern"
        )


class TestAssessmentOutputMetadata:
    """Tests for metadata in assessment output (7d)."""

    def test_assessment_output_has_metadata(self):
        """Verify the JSON output contains a metadata key."""
        with patch("sast_triage.agent.ChatVertexAI") as mock_chat:
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_chat.return_value = mock_llm

            from sast_triage.agent import SASTTriageAgent

            agent = SASTTriageAgent(
                project="test-project",
                location="test-location",
                model_name="test-model",
                project_name="myproject",
                project_id="proj-123",
                scan_id="scan-456",
                branch="main",
            )

        results = [
            {
                "resultHash": "hash-001",
                "is_vulnerable": True,
                "confidence": 0.9,
                "suggested_state": "CONFIRMED",
                "justification": "Exploitable",
            },
            {
                "resultHash": "hash-002",
                "is_vulnerable": False,
                "confidence": 0.8,
                "suggested_state": "PROPOSED_NOT_EXPLOITABLE",
                "justification": "Likely safe",
            },
        ]

        output = agent._build_assessment_output(results)

        assert "metadata" in output
        assert "results" in output
        assert output["metadata"]["project_name"] == "myproject"
        assert output["metadata"]["project_id"] == "proj-123"
        assert output["metadata"]["scan_id"] == "scan-456"
        assert output["metadata"]["branch"] == "main"
        assert output["metadata"]["model"] == "test-model"
        assert output["metadata"]["total_findings"] == 2
        assert output["metadata"]["summary"]["confirmed"] == 1
        assert output["metadata"]["summary"]["not_exploitable"] == 0
        assert output["metadata"]["summary"]["proposed_not_exploitable"] == 1
        assert output["metadata"]["summary"]["refused"] == 0
        assert output["metadata"]["summary"]["refusal_rate"] == 0.0
        assert len(output["results"]) == 2


class TestPreprocessingLogging:
    """Tests for preprocessing reports in session log (7e)."""

    def test_preprocessing_logged_obfuscation(self, tmp_path):
        """Verify obfuscation report appears in session log."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        report = FakeObfuscationReport()
        mgr.log_preprocessing(obfuscation_report=report)

        with open(mgr.log_file) as f:
            log = json.load(f)

        obf = log["preprocessing"]["obfuscation"]
        assert obf["files_processed"] == 10
        assert obf["files_modified"] == 3
        assert obf["total_replacements"] == 25
        assert obf["replacements_by_type"]["ip_address"] == 15

    def test_preprocessing_logged_masking(self, tmp_path):
        """Verify masking report appears in session log."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        report = FakeMaskingReport()
        mgr.log_preprocessing(masking_report=report)

        with open(mgr.log_file) as f:
            log = json.load(f)

        mask = log["preprocessing"]["secret_masking"]
        assert mask["csv_path"] == "gitleaks.csv"
        assert mask["total_entries"] == 50
        assert mask["secrets_masked"] == 12
        assert mask["files_modified"] == 5
        assert mask["skipped"] == 1

    def test_preprocessing_logged_both(self, tmp_path):
        """Verify both reports can be logged together."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        mgr.log_preprocessing(
            obfuscation_report=FakeObfuscationReport(),
            masking_report=FakeMaskingReport(),
        )

        with open(mgr.log_file) as f:
            log = json.load(f)

        assert "obfuscation" in log["preprocessing"]
        assert "secret_masking" in log["preprocessing"]


class TestSystemPromptDedup:
    """System prompt is recorded once at session level; per-finding entries
    reference it by hash. This applies in both compact and non-compact mode
    so big runs don't duplicate the same prompt N times."""

    def test_first_call_records_full_system_prompt_at_session_level(
        self, tmp_path
    ):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=False,
        )
        mgr.log_file = tmp_path / "test_log.json"
        finding_log = mgr.log_finding_start("hash-001")

        mgr.log_initial_inputs(finding_log, "SYS PROMPT", "HUMAN PROMPT")

        with open(mgr.log_file) as f:
            log = json.load(f)
        meta = log["session_metadata"]
        assert meta["system_prompt"] == "SYS PROMPT"
        assert meta["system_prompt_hash"] == _hash_prompt("SYS PROMPT")

    def test_per_finding_system_entry_is_hash_reference(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=False,
        )
        mgr.log_file = tmp_path / "test_log.json"
        finding_log = mgr.log_finding_start("hash-001")

        mgr.log_initial_inputs(finding_log, "SYS PROMPT", "HUMAN PROMPT")

        with open(mgr.log_file) as f:
            log = json.load(f)
        sys_entry = log["findings_processed"][0]["conversation"][0]
        assert sys_entry["type"] == "system"
        sys_hash = _hash_prompt("SYS PROMPT")
        assert sys_hash in sys_entry["content"]
        assert "session_metadata.system_prompt" in sys_entry["content"]

    def test_repeated_calls_do_not_duplicate_session_level_prompt(
        self, tmp_path
    ):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=False,
        )
        mgr.log_file = tmp_path / "test_log.json"

        for hash_id in ("hash-001", "hash-002", "hash-003"):
            f_log = mgr.log_finding_start(hash_id)
            mgr.log_initial_inputs(f_log, "SYS PROMPT", f"HUMAN {hash_id}")

        with open(mgr.log_file) as f:
            log = json.load(f)
        # session-level system_prompt is stored exactly once
        assert log["session_metadata"]["system_prompt"] == "SYS PROMPT"
        # each finding has a hash-reference stub, not the full prompt
        for finding in log["findings_processed"]:
            sys_entry = finding["conversation"][0]
            assert sys_entry["content"].startswith("<see ")


class TestCompactLogs:
    """Tests for the opt-in --compact-logs mode."""

    def test_compact_logs_flag_recorded_in_session_metadata(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        mgr.save_log()

        with open(mgr.log_file) as f:
            log = json.load(f)
        assert log["session_metadata"]["compact_logs"] is True

    def test_compact_logs_default_off(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
        )
        mgr.log_file = tmp_path / "test_log.json"
        mgr.save_log()

        with open(mgr.log_file) as f:
            log = json.load(f)
        assert log["session_metadata"]["compact_logs"] is False

    def test_compact_omits_system_prompt_full_text(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        mgr.log_initial_inputs(f_log, "VERY LONG SYSTEM PROMPT", "human")

        with open(mgr.log_file) as f:
            log = json.load(f)
        meta = log["session_metadata"]
        assert meta["system_prompt_hash"] == _hash_prompt(
            "VERY LONG SYSTEM PROMPT"
        )
        assert "system_prompt" not in meta

    def test_compact_strips_human_input_prompt(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("abc123")

        mgr.log_initial_inputs(
            f_log, "SYS", "huge finding_details JSON here..."
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        human_entry = log["findings_processed"][0]["conversation"][1]
        assert human_entry["type"] == "human"
        assert "huge finding_details" not in human_entry["content"]
        assert "abc123" in human_entry["content"]
        assert "<stripped" in human_entry["content"]

    def test_non_compact_keeps_full_human_input_prompt(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=False,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("abc123")

        mgr.log_initial_inputs(
            f_log, "SYS", "huge finding_details JSON here..."
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        human_entry = log["findings_processed"][0]["conversation"][1]
        assert human_entry["content"] == "huge finding_details JSON here..."

    def test_compact_does_not_strip_subsequent_human_nudges(self, tmp_path):
        """Nudge prompts via log_message stay verbatim — only the initial
        finding input prompt is stripped."""
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        mgr.log_initial_inputs(f_log, "SYS", "INPUT PROMPT")
        mgr.log_message(f_log, "human", "You must use a tool.")

        with open(mgr.log_file) as f:
            log = json.load(f)
        nudge_entry = log["findings_processed"][0]["conversation"][2]
        assert nudge_entry["type"] == "human"
        assert nudge_entry["content"] == "You must use a tool."

    def test_compact_strips_read_file_content_array(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        result = {
            "file": "src/Foo.java",
            "total_lines": 142,
            "content": [f"{i}: line {i}" for i in range(1, 143)],
        }
        mgr.log_tool_result(
            f_log, "read_file", {"file_path": "src/Foo.java"}, result
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        result_entry = log["findings_processed"][0]["conversation"][0]
        assert "line 1" not in result_entry["result"]
        assert "line 142" not in result_entry["result"]
        assert "_stripped" in result_entry["result"]
        assert "142 lines" in result_entry["result"]
        assert "src/Foo.java" in result_entry["result"]

    def test_compact_strips_list_directory_items(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        result = {
            "directory": "src",
            "total_items": 3,
            "items": [
                {"name": "a.java", "type": "file", "size": 100},
                {"name": "b.java", "type": "file", "size": 200},
                {"name": "sub", "type": "directory", "size": None},
            ],
        }
        mgr.log_tool_result(
            f_log, "list_directory", {"directory_path": "src"}, result
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        result_entry = log["findings_processed"][0]["conversation"][0]
        assert "a.java" not in result_entry["result"]
        assert "_stripped" in result_entry["result"]
        assert "3 items" in result_entry["result"]

    def test_compact_strips_search_in_files_results(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        result = {
            "pattern": "secret",
            "file_extensions": "java",
            "matches_found": 2,
            "results": [
                {"file": "A.java", "line": 10, "content": "secret = 'x'"},
                {"file": "B.java", "line": 20, "content": "secret = 'y'"},
            ],
        }
        mgr.log_tool_result(
            f_log,
            "search_in_files",
            {"pattern": "secret", "file_extensions": "java"},
            result,
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        result_entry = log["findings_processed"][0]["conversation"][0]
        assert "A.java" not in result_entry["result"]
        assert "B.java" not in result_entry["result"]
        assert "_stripped" in result_entry["result"]
        assert "2 matches" in result_entry["result"]

    def test_compact_passes_through_non_bulk_tool_results(self, tmp_path):
        """parse_csv_findings, get_finding_details, etc. are not in the
        bulk-fields map and should not be touched."""
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=True,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        decision_result = {
            "status": "decision_submitted",
            "is_vulnerable": False,
            "confidence": 0.9,
            "justification": "input is sanitized via X.sanitize()",
        }
        mgr.log_tool_result(
            f_log,
            "submit_triage_decision",
            {"is_vulnerable": False, "confidence": 0.9},
            decision_result,
        )

        with open(mgr.log_file) as f:
            log = json.load(f)
        result_entry = log["findings_processed"][0]["conversation"][0]
        assert "sanitized via X.sanitize()" in result_entry["result"]
        assert "_stripped" not in result_entry["result"]

    def test_non_compact_keeps_read_file_content(self, tmp_path):
        mgr = AgentLoggingManager(
            model_name="gemini-2.5-pro",
            temperature=0.1,
            compact_logs=False,
        )
        mgr.log_file = tmp_path / "test_log.json"
        f_log = mgr.log_finding_start("hash-001")

        result = {"file": "x.java", "total_lines": 1, "content": ["1: x"]}
        mgr.log_tool_result(f_log, "read_file", {"file_path": "x"}, result)

        with open(mgr.log_file) as f:
            log = json.load(f)
        result_entry = log["findings_processed"][0]["conversation"][0]
        assert "1: x" in result_entry["result"]
        assert "_stripped" not in result_entry["result"]


class TestCompactToolResultHelper:
    """Direct tests for the _compact_tool_result helper."""

    def test_drops_content_for_read_file(self):
        out = _compact_tool_result(
            "read_file",
            {"file": "x", "total_lines": 3, "content": ["1: a", "2: b", "3: c"]},
        )
        assert "content" not in out
        assert out["_stripped"] == "<3 lines>"
        assert out["file"] == "x"
        assert out["total_lines"] == 3

    def test_drops_items_for_list_directory(self):
        out = _compact_tool_result(
            "list_directory",
            {"directory": ".", "total_items": 2, "items": [{}, {}]},
        )
        assert "items" not in out
        assert out["_stripped"] == "<2 items>"

    def test_drops_results_for_search_in_files(self):
        out = _compact_tool_result(
            "search_in_files",
            {"pattern": "x", "matches_found": 1, "results": [{}]},
        )
        assert "results" not in out
        assert out["_stripped"] == "<1 matches>"

    def test_passes_through_unknown_tool(self):
        result = {"foo": "bar", "items": [1, 2, 3]}
        assert _compact_tool_result("unknown_tool", result) == result

    def test_passes_through_non_dict(self):
        assert _compact_tool_result("read_file", "string") == "string"
        assert _compact_tool_result("read_file", None) is None

    def test_passes_through_when_bulk_field_missing(self):
        result = {"file": "x", "total_lines": 0}
        assert _compact_tool_result("read_file", result) == result


class TestThoughtSignatureStripping:
    """Strip Gemini ``thought_signature`` from logged content while keeping
    the original message intact for the next LLM turn."""

    def test_strip_signatures_passes_plain_string_through(self):
        assert _strip_signatures("just a string") == "just a string"

    def test_strip_signatures_passes_none_through(self):
        assert _strip_signatures(None) is None

    def test_strip_signatures_drops_signature_key_from_part(self):
        content = [
            {
                "type": "text",
                "text": "I will start by reading the file.",
                "thought_signature": "Cq8JAY89...opaque...",
            }
        ]
        cleaned = _strip_signatures(content)
        assert cleaned == [
            {"type": "text", "text": "I will start by reading the file."}
        ]

    def test_strip_signatures_keeps_parts_without_signature_unchanged(self):
        content = [
            {"type": "text", "text": "no signature here"},
            "raw string part",
        ]
        cleaned = _strip_signatures(content)
        assert cleaned == content

    def test_strip_signatures_does_not_mutate_input(self):
        original = [
            {
                "type": "text",
                "text": "preamble",
                "thought_signature": "opaque",
            }
        ]
        original_snapshot = [dict(part) for part in original]
        _strip_signatures(original)
        assert original == original_snapshot

    def test_log_message_strips_signature_from_assistant_content(
        self, tmp_path
    ):
        mgr = AgentLoggingManager(model_name="gemini-2.5-pro", temperature=0.1)
        mgr.log_file = tmp_path / "test_log.json"
        finding_log = mgr.log_finding_start("hash-001")

        assistant_content = [
            {
                "type": "text",
                "text": "I will start by analyzing the source.",
                "thought_signature": "Cq8JAY89...opaque...",
            }
        ]
        mgr.log_message(
            finding_log,
            "assistant",
            assistant_content,
            tool_calls=[{"name": "read_file", "args": {"file_path": "x"}}],
        )

        # Original is unchanged so the next LLM turn still has the signature.
        assert "thought_signature" in assistant_content[0]

        # On disk, the signature is gone.
        with open(mgr.log_file) as f:
            log = json.load(f)
        logged_entry = log["findings_processed"][0]["conversation"][0]
        assert logged_entry["content"] == [
            {"type": "text", "text": "I will start by analyzing the source."}
        ]
        assert logged_entry["tool_calls"] == [
            {"name": "read_file", "args": {"file_path": "x"}}
        ]

    def test_log_message_leaves_plain_string_content_alone(self, tmp_path):
        mgr = AgentLoggingManager(model_name="gemini-2.5-pro", temperature=0.1)
        mgr.log_file = tmp_path / "test_log.json"
        finding_log = mgr.log_finding_start("hash-002")

        mgr.log_message(finding_log, "assistant", "plain text response")

        with open(mgr.log_file) as f:
            log = json.load(f)
        logged_entry = log["findings_processed"][0]["conversation"][0]
        assert logged_entry["content"] == "plain text response"


class TestSessionSummary:
    """Tests for session summary (7b cumulative totals)."""

    def test_session_summary(self, tmp_path):
        """Verify session summary includes total tokens and finding counts."""
        mgr = AgentLoggingManager(
            model_name="test-model",
            temperature=0.0,
        )
        mgr.log_file = tmp_path / "test_log.json"

        # Simulate two findings with token usage
        finding1 = mgr.log_finding_start("hash-001")
        mgr.log_token_usage(
            finding1,
            {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        )
        decision1 = TriageDecision(
            resultHash="hash-001",
            is_vulnerable=True,
            confidence=0.9,
            suggested_state="CONFIRMED",
            justification="Exploitable",
        )
        mgr.log_finding_complete(finding1, decision1)

        finding2 = mgr.log_finding_start("hash-002")
        mgr.log_token_usage(
            finding2,
            {"input_tokens": 200, "output_tokens": 80, "total_tokens": 280},
        )
        decision2 = TriageDecision(
            resultHash="hash-002",
            is_vulnerable=False,
            confidence=0.8,
            suggested_state="NOT_EXPLOITABLE",
            justification="Safe",
        )
        mgr.log_finding_complete(finding2, decision2)

        triage_results = [
            decision1.model_dump(),
            decision2.model_dump(),
        ]
        mgr.finalize_session(triage_results)

        with open(mgr.log_file) as f:
            log = json.load(f)

        summary = log["session_summary"]
        assert summary["total_findings"] == 2
        assert summary["confirmed"] == 1
        assert summary["not_exploitable"] == 1
        assert summary["proposed_not_exploitable"] == 0
        assert summary["refused"] == 0
        assert summary["refusal_rate"] == 0.0
        assert summary["total_tokens"]["input"] == 300
        assert summary["total_tokens"]["output"] == 130
        assert summary["total_tokens"]["total"] == 430
        assert "session_end" in summary
