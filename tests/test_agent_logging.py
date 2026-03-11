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

from sast_triage.agent_logging import AgentLoggingManager
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
                "assessment_result": "CONFIRMED",
                "assessment_confidence": 0.9,
                "assessment_justification": "Exploitable",
            },
            {
                "resultHash": "hash-002",
                "assessment_result": "NOT_EXPLOITABLE",
                "assessment_confidence": 0.8,
                "assessment_justification": "Safe",
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
        assert output["metadata"]["summary"]["not_exploitable"] == 1
        assert output["metadata"]["summary"]["refused"] == 0
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
            assessment_result="CONFIRMED",
            assessment_confidence=0.9,
            assessment_justification="Exploitable",
        )
        mgr.log_finding_complete(finding1, decision1)

        finding2 = mgr.log_finding_start("hash-002")
        mgr.log_token_usage(
            finding2,
            {"input_tokens": 200, "output_tokens": 80, "total_tokens": 280},
        )
        decision2 = TriageDecision(
            resultHash="hash-002",
            assessment_result="NOT_EXPLOITABLE",
            assessment_confidence=0.8,
            assessment_justification="Safe",
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
        assert summary["refused"] == 0
        assert summary["total_tokens"]["input"] == 300
        assert summary["total_tokens"]["output"] == 130
        assert summary["total_tokens"]["total"] == 430
        assert "session_end" in summary
