"""
Test suite for SAST Triage Agent core functionality
"""

import csv
import inspect
import os
import sys
import pytest
import json
import asyncio
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.agent import SASTTriageAgent
from sast_triage.agent_models import TriageDecision
from utils.llm_factory import NodeLLMConfig, TriageLLMConfig


def _single_model_config(model: str = "test-model", location: str = "test-location"):
    """A TriageLLMConfig with every node on the same model and region."""
    node = NodeLLMConfig(model=model, location=location)
    return TriageLLMConfig(research=node, analyst=node, critic=node)


def test_agent_config_snapshot_includes_non_convergent_cap():
    # The session_start snapshot self-documents the active tuning knobs, so the
    # non-convergent confidence cap (the clamp) must appear alongside the others.
    from config import NON_CONVERGENT_CONFIDENCE_CAP

    snapshot = SASTTriageAgent._agent_config_snapshot()
    assert (
        snapshot["NON_CONVERGENT_CONFIDENCE_CAP"]
        == NON_CONVERGENT_CONFIDENCE_CAP
    )


def test_agent_config_snapshot_includes_research_stall_limit():
    # The honest-termination stall limit is a tuning knob, so it belongs in the
    # session_start snapshot alongside the other per-finding-graph constants.
    from config import MAX_RESEARCH_STALL

    snapshot = SASTTriageAgent._agent_config_snapshot()
    assert snapshot["MAX_RESEARCH_STALL"] == MAX_RESEARCH_STALL


class TestSASTTriageAgent:
    """Test the main SAST Triage Agent class."""
    
    @pytest.fixture
    def agent(self):
        """Create an agent instance for testing."""
        with patch("sast_triage.agent.build_chat_model") as mock_factory:
            # Mock the LLM; bind_tools/with_structured_output/with_config chain
            # back to the same mock.
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_factory.return_value = mock_llm

            agent = SASTTriageAgent(
                project="test-project",
                llm_config=_single_model_config(),
                temperature=0.1,
            )
            # Store the mock for later access in tests
            agent._mock_llm = mock_llm
            return agent
    
    @pytest.fixture
    def test_findings_path(self):
        """Path to test findings."""
        return os.path.join(os.path.dirname(__file__), "test_data", "findings")
    
    def test_agent_initialization(self, agent):
        """Test that agent initializes correctly."""
        assert agent.models == {
            "research": "test-model",
            "analyst": "test-model",
            "critic": "test-model",
        }
        assert agent.temperature == 0.1
        # The researcher gets the three investigation tools; verdict and review
        # are handled by the analyst and critic graph nodes, not tools.
        assert len(agent.research_tools) == 3
        assert agent.per_finding_graph is not None
    
    def test_update_csv_status(self, agent, tmp_path):
        """Test CSV status update functionality."""
        # Create a test CSV with state column
        csv_path = tmp_path / "test.csv"
        csv_content = (
            "resultHash,severity,state,triaged\n"
            "hash-001,HIGH,TO_VERIFY,no\n"
            "hash-002,MEDIUM,TO_VERIFY,no\n"
        )
        csv_path.write_text(csv_content)

        # Update status for hash-001
        agent.update_csv_status("hash-001", str(csv_path))

        # Read and verify
        updated_content = csv_path.read_text()

        # Check that hash-001 is marked as triaged
        assert "hash-001,HIGH,TO_VERIFY,yes" in updated_content
        assert "hash-002,MEDIUM,TO_VERIFY,no" in updated_content

    def test_update_csv_status_default_path(self):
        """Verify update_csv_status default parameter is FINDINGS_CSV_FILE."""
        from config import FINDINGS_CSV_FILE

        sig = inspect.signature(SASTTriageAgent.update_csv_status)
        csv_path_param = sig.parameters["csv_path"]
        assert csv_path_param.default == FINDINGS_CSV_FILE
    
    def test_save_incremental_result(self, agent, tmp_path):
        """Test saving incremental results with metadata wrapper."""
        assessments_file = tmp_path / "findings_assessment.json"
        agent.assessments_file = str(assessments_file)

        result1 = {
            "resultHash": "hash-001",
            "is_vulnerable": True,
            "confidence": 0.9,
            "suggested_state": "CONFIRMED",
            "justification": "Test justification 1",
        }
        agent.save_incremental_result(result1)

        assert assessments_file.exists()
        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert "metadata" in data
        assert "results" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["resultHash"] == "hash-001"

        result2 = {
            "resultHash": "hash-002",
            "is_vulnerable": False,
            "confidence": 0.8,
            "suggested_state": "PROPOSED_NOT_EXPLOITABLE",
            "justification": "Test justification 2",
        }
        agent.save_incremental_result(result2)

        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert len(data["results"]) == 2
        assert data["results"][1]["resultHash"] == "hash-002"

        # Update existing result
        result1_updated = {
            "resultHash": "hash-001",
            "is_vulnerable": False,
            "confidence": 0.95,
            "suggested_state": "NOT_EXPLOITABLE",
            "justification": "Updated justification",
        }
        agent.save_incremental_result(result1_updated)

        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert len(data["results"]) == 2
        assert data["results"][0]["suggested_state"] == "NOT_EXPLOITABLE"
        assert data["results"][0]["confidence"] == 0.95
    
    def test_get_pending_findings(self, agent, test_findings_path):
        """Test getting pending findings from CSV."""
        csv_path = os.path.join(test_findings_path, "triage_list.csv")

        mock_results = [
            {"resultHash": "hash-001", "severity": "HIGH", "triaged": "no"},
            {"resultHash": "hash-002", "severity": "MEDIUM", "triaged": "no"},
            {"resultHash": "hash-003", "severity": "LOW", "triaged": "yes"},
        ]

        with patch("sast_triage.agent.parse_csv_findings") as mock_tool:
            mock_tool.invoke.return_value = mock_results

            pending = agent.get_pending_findings(csv_path)

            assert len(pending) == 2
            assert all(f["triaged"] == "no" for f in pending)
            assert pending[0]["resultHash"] == "hash-001"
            assert pending[1]["resultHash"] == "hash-002"
    
    @pytest.mark.asyncio
    async def test_analyze_single_finding_with_error(self, agent):
        """Test analyze_single_finding when finding details can't be loaded."""
        with patch("sast_triage.agent.get_finding_details") as mock_tool:
            mock_tool.invoke.return_value = {"error": "Finding not found"}

            decision = await agent.analyze_single_finding("nonexistent-finding")

            assert decision.resultHash == "nonexistent-finding"
            assert decision.is_vulnerable is None
            assert decision.suggested_state == "REFUSED"
            assert decision.confidence == 0.0
            assert "Could not load finding details" in decision.justification

    @pytest.mark.asyncio
    async def test_analyze_single_finding_invokes_graph_and_returns_verdict(
        self, agent
    ):
        """The agent builds state, runs the graph and returns its verdict."""
        finding_data = {
            "resultHash": "hash-001",
            "severity": "HIGH",
            "queryName": "SQL_Injection",
            "cweID": "89",
            "dataflow": [],
        }
        graph_verdict = TriageDecision(
            resultHash="hash-001",
            is_vulnerable=True,
            confidence=0.88,
            suggested_state="CONFIRMED",
            justification="Direct SQL concatenation detected",
            agreement_rate=1.0,
            sample_count=2,
        )

        with patch("sast_triage.agent.get_finding_details") as mock_tool:
            mock_tool.invoke.return_value = finding_data

            agent.per_finding_graph = Mock()
            agent.per_finding_graph.ainvoke = AsyncMock(
                return_value={"verdict": graph_verdict}
            )

            decision = await agent.analyze_single_finding("hash-001")

            # The agent passed a TriageState built from the finding to the graph.
            state_arg = agent.per_finding_graph.ainvoke.call_args.args[0]
            assert state_arg.finding.resultHash == "hash-001"
            assert state_arg.checklist.checklist_id == "sqli"
            # And returned the graph's verdict unchanged.
            assert decision is graph_verdict
            assert decision.suggested_state == "CONFIRMED"
            assert decision.agreement_rate == 1.0


class TestPerNodeModels:
    """The agent builds each LLM node from its own model and location via
    build_chat_model, so research, analyst and critic can run different
    providers and regions."""

    @staticmethod
    def _llm_config():
        from utils.llm_factory import NodeLLMConfig, TriageLLMConfig

        return TriageLLMConfig(
            research=NodeLLMConfig(model="gemini-2.5-pro", location="europe-west4"),
            analyst=NodeLLMConfig(model="gemini-2.5-flash", location="europe-west4"),
            critic=NodeLLMConfig(model="claude-sonnet-4@20250514", location="us-east5"),
        )

    @contextmanager
    def _agent(self):
        with patch("sast_triage.agent.build_chat_model") as mock_factory:
            mock_factory.side_effect = lambda *a, **k: Mock()
            agent = SASTTriageAgent(
                project="proj-x",
                llm_config=self._llm_config(),
                temperature=0.1,
            )
            yield agent, mock_factory

    def test_research_and_critic_clients_built_from_their_node_config(self):
        with self._agent() as (_, mock_factory):
            calls = {c.args[0]: c.kwargs for c in mock_factory.call_args_list}
            # Research builds at the base temperature, critic at CRITIC_TEMPERATURE.
            from config import CRITIC_TEMPERATURE

            assert calls["gemini-2.5-pro"]["location"] == "europe-west4"
            assert calls["gemini-2.5-pro"]["temperature"] == 0.1
            assert calls["claude-sonnet-4@20250514"]["location"] == "us-east5"
            assert (
                calls["claude-sonnet-4@20250514"]["temperature"]
                == CRITIC_TEMPERATURE
            )
            assert all(
                c.kwargs["project"] == "proj-x"
                for c in mock_factory.call_args_list
            )

    def test_analyst_client_built_from_analyst_node_config(self):
        with self._agent() as (agent, mock_factory):
            mock_factory.reset_mock()
            agent._analyst_llm_for(0.3)
            _, kwargs = mock_factory.call_args
            assert mock_factory.call_args.args[0] == "gemini-2.5-flash"
            assert kwargs["location"] == "europe-west4"
            assert kwargs["temperature"] == 0.3

    def test_models_map_exposes_per_node_model_names(self):
        with self._agent() as (agent, _):
            assert agent.models == {
                "research": "gemini-2.5-pro",
                "analyst": "gemini-2.5-flash",
                "critic": "claude-sonnet-4@20250514",
            }


class TestTriageDecision:
    """Test the TriageDecision model."""

    def test_triage_decision_creation(self):
        """Test creating a TriageDecision."""
        decision = TriageDecision(
            resultHash="hash-001",
            is_vulnerable=True,
            confidence=0.85,
            suggested_state="CONFIRMED",
            justification="Test justification",
        )

        assert decision.resultHash == "hash-001"
        assert decision.is_vulnerable is True
        assert decision.confidence == 0.85
        assert decision.suggested_state == "CONFIRMED"
        assert decision.justification == "Test justification"
        assert decision.agreement_rate is None
        assert decision.sample_count is None

    def test_triage_decision_dict(self):
        """Test converting TriageDecision to dict."""
        decision = TriageDecision(
            resultHash="hash-001",
            is_vulnerable=False,
            confidence=0.75,
            suggested_state="PROPOSED_NOT_EXPLOITABLE",
            justification="Not exploitable because...",
        )

        decision_dict = decision.model_dump()
        assert decision_dict["resultHash"] == "hash-001"
        assert decision_dict["is_vulnerable"] is False
        assert decision_dict["confidence"] == 0.75
        assert decision_dict["suggested_state"] == "PROPOSED_NOT_EXPLOITABLE"
        assert decision_dict["justification"] == "Not exploitable because..."


class TestOutputPathSafety:
    """The agent must create its output directory and route assessment-file
    I/O through io_safe, so a write succeeds on a fresh output path and on a
    Windows path past the 260-char MAX_PATH limit. io_safe is a no-op on POSIX,
    so these run unchanged on Linux and macOS."""

    def _agent(self, **kwargs):
        with patch("sast_triage.agent.build_chat_model") as mock_factory:
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_factory.return_value = mock_llm
            return SASTTriageAgent(
                project="p", llm_config=_single_model_config("m", "l"), **kwargs
            )

    def test_init_creates_missing_output_directory(self, tmp_path):
        out = tmp_path / "fresh" / "nested"
        assert not out.exists()
        self._agent(project_name="proj", output_dir=str(out))
        assert out.exists()

    def test_save_incremental_result_routes_write_through_io_safe(self, tmp_path):
        agent = self._agent(project_name="proj", output_dir=str(tmp_path / "o"))
        result = {
            "resultHash": "hash-1",
            "is_vulnerable": True,
            "confidence": 0.9,
            "suggested_state": "CONFIRMED",
            "justification": "j",
        }
        with patch(
            "sast_triage.agent.io_safe", side_effect=lambda p: p
        ) as mock_io_safe:
            agent.save_incremental_result(result)

        assert any(
            call.args and call.args[0] == agent.assessments_file
            for call in mock_io_safe.call_args_list
        )
        assert os.path.exists(agent.assessments_file)


def test_process_summary_from_state_counts_evidence_and_loops():
    from sast_triage.agent import _process_summary_from_state
    from sast_triage.graph.state import (
        CodeEvidence,
        EvidenceBundle,
        ToolCallRecord,
    )

    final_state = {
        "evidence": EvidenceBundle(
            items=[CodeEvidence(file_path="a.py", content="x")]
        ),
        "failed_tool_calls": [ToolCallRecord(tool_name="t", error="boom")],
        "reanalysis_count": 2,
        "research_stall_streak": 1,
    }
    summary = _process_summary_from_state(final_state)
    assert summary == {
        "evidence_items_count": 1,
        "failed_tool_calls_count": 1,
        "reanalysis_count": 2,
        "research_stall_streak": 1,
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
