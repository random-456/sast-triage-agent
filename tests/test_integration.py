"""
Integration tests for SAST Triage Agent
"""

import os
import sys
import pytest
import json
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.agent import SASTTriageAgent
from sast_triage.models import TriageDecision


class TestIntegration:
    """End-to-end integration tests."""
    
    @pytest.fixture
    def test_data_path(self):
        """Path to test data."""
        return os.path.join(os.path.dirname(__file__), "test_data")
    
    @pytest.fixture
    def mock_llm_agent(self, test_data_path):
        """Create an agent with mocked LLM for deterministic testing."""
        with patch('sast_triage.agent.ChatOpenAI') as mock_chat:
            # Mock the LLM
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_chat.return_value = mock_llm
            
            agent = SASTTriageAgent(
                base_url="http://test.local",
                model_name="test-model",
                api_key="test-key",
                temperature=0.0
            )
            
            # Store the mock for test access
            agent._mock_llm = mock_llm
            
            # Set test paths
            test_codebase = os.path.join(test_data_path, "codebase")
            test_findings = os.path.join(test_data_path, "findings")
            
            # Patch the paths
            with patch('sast_triage.tools.CODEBASE_PATH', test_codebase):
                with patch('sast_triage.config.CODEBASE_PATH', test_codebase):
                    with patch('sast_triage.config.FINDINGS_PATH', test_findings):
                        with patch('sast_triage.config.DEFAULT_CSV_FILE', 
                                  os.path.join(test_findings, "triage_list.csv")):
                            with patch('sast_triage.config.DEFAULT_JSON_FILE',
                                      os.path.join(test_findings, "findings_details.json")):
                                yield agent
    
    @pytest.mark.asyncio
    async def test_full_workflow_sql_injection_confirmed(self, mock_llm_agent, test_data_path, tmp_path, monkeypatch):
        """Test full workflow with SQL injection that should be confirmed."""
        # Change to temp directory for output files
        monkeypatch.chdir(tmp_path)
        
        # Setup paths
        test_codebase = os.path.join(test_data_path, "codebase")
        test_findings = os.path.join(test_data_path, "findings")
        
        # Create a sequence of mock LLM responses
        responses = []
        
        # Response 1: Initial analysis with file read
        resp1 = Mock()
        resp1.content = "I need to examine the vulnerable.js file to understand the SQL injection."
        resp1.tool_calls = [{
            "id": "call-1",
            "name": "read_file",
            "args": {"file_path": "vulnerable.js"}
        }]
        responses.append(resp1)
        
        # Response 2: Analysis after reading file
        resp2 = Mock()
        resp2.content = "I can see direct string concatenation with user input in the SQL query. This is vulnerable."
        resp2.tool_calls = [{
            "id": "call-2",
            "name": "submit_triage_decision",
            "args": {
                "is_exploitable": True,
                "confidence": 0.95,
                "justification": "Direct SQL injection vulnerability confirmed. User input from req.query.id is directly concatenated into SQL query without sanitization."
            }
        }]
        responses.append(resp2)
        
        # Mock the LLM to return our responses
        mock_llm_agent.llm_with_tools = Mock()
        mock_llm_agent.llm_with_tools.ainvoke = AsyncMock(side_effect=responses)
        
        # Patch the paths for the tools
        with patch('sast_triage.tools.CODEBASE_PATH', test_codebase):
            with patch('sast_triage.agent.get_finding_details') as mock_get_details:
                # Return the SQL injection finding details
                mock_get_details.return_value = {
                    "findingId": "test-sql-001",
                    "severity": "HIGH",
                    "queryName": "SQL_Injection",
                    "cweID": 89,
                    "dataflow": [
                        {
                            "fileName": "/vulnerable.js",
                            "line": "10",
                            "column": "19",
                            "method": "get",
                            "name": "userId",
                            "domType": "source"
                        },
                        {
                            "fileName": "/vulnerable.js",
                            "line": "12",
                            "column": "17",
                            "method": "get",
                            "name": "query",
                            "domType": "sink"
                        }
                    ]
                }
                
                # Run analysis
                decision = await mock_llm_agent.analyze_single_finding("test-sql-001")
                
                # Verify decision
                assert decision.findingId == "test-sql-001"
                assert decision.assessment_result == "CONFIRMED"
                assert decision.assessment_confidence == 0.95
                assert "Direct SQL injection" in decision.assessment_justification
    
    @pytest.mark.asyncio
    async def test_full_workflow_file_not_found(self, mock_llm_agent, test_data_path, tmp_path, monkeypatch):
        """Test workflow when referenced file doesn't exist."""
        # Change to temp directory for output files
        monkeypatch.chdir(tmp_path)
        
        # Setup paths
        test_codebase = os.path.join(test_data_path, "codebase")
        test_findings = os.path.join(test_data_path, "findings")
        
        # Create mock LLM responses
        responses = []
        
        # Response 1: Try to read nonexistent file
        resp1 = Mock()
        resp1.content = "I need to examine the nonexistent.js file."
        resp1.tool_calls = [{
            "id": "call-1",
            "name": "read_file",
            "args": {"file_path": "nonexistent.js"}
        }]
        responses.append(resp1)
        
        # Response 2: Handle file not found
        resp2 = Mock()
        resp2.content = "The file doesn't exist, so I cannot verify the vulnerability."
        resp2.tool_calls = [{
            "id": "call-2",
            "name": "submit_triage_decision",
            "args": {
                "is_exploitable": False,
                "confidence": 0.0,
                "justification": "Cannot analyze - referenced file does not exist in codebase."
            }
        }]
        responses.append(resp2)
        
        # Mock the LLM
        mock_llm_agent.llm_with_tools = Mock()
        mock_llm_agent.llm_with_tools.ainvoke = AsyncMock(side_effect=responses)
        
        # Patch the paths
        with patch('sast_triage.tools.CODEBASE_PATH', test_codebase):
            with patch('sast_triage.agent.get_finding_details') as mock_get_details:
                # Return the XSS finding that references nonexistent file
                mock_get_details.return_value = {
                    "findingId": "test-xss-002",
                    "severity": "MEDIUM",
                    "queryName": "XSS_Reflected",
                    "dataflow": [
                        {"fileName": "/nonexistent.js", "line": "15", "domType": "source"},
                        {"fileName": "/nonexistent.js", "line": "20", "domType": "sink"}
                    ]
                }
                
                # Run analysis
                decision = await mock_llm_agent.analyze_single_finding("test-xss-002")
                
                # Verify decision
                assert decision.findingId == "test-xss-002"
                assert decision.assessment_result == "NOT_EXPLOITABLE"
                assert decision.assessment_confidence == 0.0
                assert "file does not exist" in decision.assessment_justification.lower()
    
    @pytest.mark.asyncio
    async def test_process_all_findings_integration(self, mock_llm_agent, test_data_path, tmp_path, monkeypatch):
        """Test processing multiple findings end-to-end."""
        # Change to temp directory for output files
        monkeypatch.chdir(tmp_path)
        
        # Copy test CSV to temp directory
        test_csv = os.path.join(test_data_path, "findings", "triage_list.csv")
        temp_csv = tmp_path / "triage_list.csv"
        temp_csv.write_text(Path(test_csv).read_text())
        
        # Setup paths
        test_codebase = os.path.join(test_data_path, "codebase")
        test_findings = os.path.join(test_data_path, "findings")
        json_file = os.path.join(test_findings, "findings_details.json")
        
        # Mock LLM to immediately submit decisions
        def create_response(finding_id, is_exploitable):
            resp = Mock()
            resp.content = f"Analyzing {finding_id}"
            resp.tool_calls = [{
                "id": f"call-{finding_id}",
                "name": "submit_triage_decision",
                "args": {
                    "is_exploitable": is_exploitable,
                    "confidence": 0.8,
                    "justification": f"Test decision for {finding_id}"
                }
            }]
            return resp
        
        # Create responses for both findings
        responses = [
            create_response("test-sql-001", True),
            create_response("test-xss-002", False)
        ]
        
        mock_llm_agent.llm_with_tools = Mock()
        mock_llm_agent.llm_with_tools.ainvoke = AsyncMock(side_effect=responses)
        
        # Run process_all_findings
        with patch('sast_triage.tools.CODEBASE_PATH', test_codebase):
            with patch('sast_triage.agent.DEFAULT_CSV_FILE', str(temp_csv)):
                with patch('sast_triage.agent.DEFAULT_JSON_FILE', json_file):
                    with patch('sast_triage.agent.parse_csv_findings') as mock_parse:
                        mock_parse.return_value = [
                            {'findingId': 'test-sql-001', 'severity': 'HIGH', 'triaged': 'no'},
                            {'findingId': 'test-xss-002', 'severity': 'MEDIUM', 'triaged': 'no'}
                        ]
                        
                        with patch('sast_triage.agent.get_finding_details') as mock_get:
                            def get_details(finding_id, json_path=None):
                                if finding_id == "test-sql-001":
                                    return {"findingId": "test-sql-001", "severity": "HIGH"}
                                else:
                                    return {"findingId": "test-xss-002", "severity": "MEDIUM"}
                            mock_get.side_effect = get_details
                            
                            results = await mock_llm_agent.process_all_findings(str(temp_csv), json_file)
        
        # Verify results
        assert len(results) == 2
        assert results[0]['findingId'] == 'test-sql-001'
        assert results[0]['assessment_result'] == 'CONFIRMED'
        assert results[1]['findingId'] == 'test-xss-002'
        assert results[1]['assessment_result'] == 'NOT_EXPLOITABLE'
        
        # Check that results were saved to file
        assert (tmp_path / "findings_assessment.json").exists()
        with open(tmp_path / "findings_assessment.json", 'r') as f:
            saved_results = json.load(f)
        assert len(saved_results) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])