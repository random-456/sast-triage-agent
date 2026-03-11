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
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.agent import SASTTriageAgent
from sast_triage.agent_models import TriageDecision


class TestSASTTriageAgent:
    """Test the main SAST Triage Agent class."""
    
    @pytest.fixture
    def agent(self):
        """Create an agent instance for testing."""
        with patch('sast_triage.agent.ChatVertexAI') as mock_chat:
            # Mock the LLM
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_chat.return_value = mock_llm
            
            agent = SASTTriageAgent(
                project="test-project",
                location="test-location",
                model_name="test-model",
                temperature=0.1
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
        assert agent.model_name == "test-model"
        assert agent.temperature == 0.1
        assert len(agent.tools) == 5
        assert agent.system_prompt is not None
        assert "security analyst" in agent.system_prompt.lower()
    
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
        """Test saving incremental results."""
        assessments_file = tmp_path / "findings_assessment.json"
        agent.assessments_file = str(assessments_file)

        result1 = {
            "resultHash": "hash-001",
            "assessment_result": "CONFIRMED",
            "assessment_confidence": 0.9,
            "assessment_justification": "Test justification 1",
        }
        agent.save_incremental_result(result1)

        assert assessments_file.exists()
        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["resultHash"] == "hash-001"

        result2 = {
            "resultHash": "hash-002",
            "assessment_result": "NOT_EXPLOITABLE",
            "assessment_confidence": 0.8,
            "assessment_justification": "Test justification 2",
        }
        agent.save_incremental_result(result2)

        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert len(data) == 2
        assert data[1]["resultHash"] == "hash-002"

        # Update existing result
        result1_updated = {
            "resultHash": "hash-001",
            "assessment_result": "NOT_EXPLOITABLE",
            "assessment_confidence": 0.95,
            "assessment_justification": "Updated justification",
        }
        agent.save_incremental_result(result1_updated)

        with open(assessments_file, "r") as f:
            data = json.load(f)
        assert len(data) == 2
        assert data[0]["assessment_result"] == "NOT_EXPLOITABLE"
        assert data[0]["assessment_confidence"] == 0.95
    
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
            assert decision.assessment_result == "REFUSED"
            assert decision.assessment_confidence == 0.0
            assert "Could not load finding details" in decision.assessment_justification

    @pytest.mark.asyncio
    async def test_analyze_single_finding_with_mock_llm(self, agent):
        """Test analyze_single_finding with mocked LLM response."""
        finding_data = {
            "resultHash": "hash-001",
            "severity": "HIGH",
            "queryName": "SQL_Injection",
            "dataflow": [],
        }

        with patch("sast_triage.agent.get_finding_details") as mock_tool:
            mock_tool.invoke.return_value = finding_data

            mock_response = Mock()
            mock_response.content = "Analyzing the SQL injection vulnerability..."
            mock_response.tool_calls = [{
                "id": "call-123",
                "name": "submit_triage_decision",
                "args": {
                    "is_exploitable": True,
                    "confidence": 0.9,
                    "justification": "Direct SQL concatenation detected",
                },
            }]

            agent.llm_with_tools = Mock()
            agent.llm_with_tools.ainvoke = AsyncMock(return_value=mock_response)

            decision = await agent.analyze_single_finding("hash-001")

            assert decision.resultHash == "hash-001"
            assert decision.assessment_result == "CONFIRMED"
            assert decision.assessment_confidence == 0.9
            assert "Direct SQL concatenation" in decision.assessment_justification


class TestTriageDecision:
    """Test the TriageDecision model."""
    
    def test_triage_decision_creation(self):
        """Test creating a TriageDecision."""
        decision = TriageDecision(
            resultHash="hash-001",
            assessment_result="CONFIRMED",
            assessment_confidence=0.85,
            assessment_justification="Test justification"
        )
        
        assert decision.resultHash == "hash-001"
        assert decision.assessment_result == "CONFIRMED"
        assert decision.assessment_confidence == 0.85
        assert decision.assessment_justification == "Test justification"
    
    def test_triage_decision_dict(self):
        """Test converting TriageDecision to dict."""
        decision = TriageDecision(
            resultHash="hash-001",
            assessment_result="NOT_EXPLOITABLE",
            assessment_confidence=0.75,
            assessment_justification="Not exploitable because..."
        )
        
        decision_dict = decision.model_dump()
        assert decision_dict["resultHash"] == "hash-001"
        assert decision_dict["assessment_result"] == "NOT_EXPLOITABLE"
        assert decision_dict["assessment_confidence"] == 0.75
        assert decision_dict["assessment_justification"] == "Not exploitable because..."


if __name__ == "__main__":
    pytest.main([__file__, "-v"])