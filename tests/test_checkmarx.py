"""Tests for Checkmarx One API client."""

import json
import unittest
from unittest.mock import Mock, patch, MagicMock

from sast_triage.api import CheckmarxClient


class TestCheckmarxClient(unittest.TestCase):
    """Test cases for CheckmarxClient."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "https://test.checkmarx.net"
        self.refresh_token = "test-refresh-token"
        self.client = CheckmarxClient(self.base_url, self.refresh_token)
    
    @patch("sast_triage.api.checkmarx_client.requests.post")
    def test_refresh_access_token_success(self, mock_post):
        """Test successful token refresh."""
        mock_response = Mock()
        mock_response.json.return_value = {"access_token": "new-access-token"}
        mock_response.ok = True
        mock_post.return_value = mock_response
        
        token = self.client.refresh_access_token()
        
        self.assertEqual(token, "new-access-token")
        self.assertEqual(self.client.access_token, "new-access-token")
        mock_post.assert_called_once()
    
    @patch("sast_triage.api.checkmarx_client.requests.post")
    def test_refresh_access_token_failure(self, mock_post):
        """Test token refresh failure."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("Auth failed")
        mock_post.return_value = mock_response
        
        with self.assertRaises(Exception) as context:
            self.client.refresh_access_token()
        
        self.assertIn("Auth failed", str(context.exception))
    
    @patch("sast_triage.api.checkmarx_client.requests.get")
    def test_get_project_details_with_repo(self, mock_get):
        """Test getting project details with repository URL."""
        self.client.access_token = "test-token"
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "12345",
            "name": "Test Project",
            "repoUrl": "https://github.com/test/repo.git"
        }
        mock_response.ok = True
        mock_get.return_value = mock_response
        
        repo_url = self.client.get_project_details("12345")
        
        self.assertEqual(repo_url, "https://github.com/test/repo.git")
        mock_get.assert_called_once()
    
    @patch("sast_triage.api.checkmarx_client.requests.get")
    def test_get_project_details_without_repo(self, mock_get):
        """Test getting project details without repository URL."""
        self.client.access_token = "test-token"
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "id": "12345",
            "name": "Test Project"
        }
        mock_response.ok = True
        mock_get.return_value = mock_response
        
        repo_url = self.client.get_project_details("12345")
        
        self.assertIsNone(repo_url)
    
    @patch("sast_triage.api.checkmarx_client.requests.get")
    def test_get_findings_for_project(self, mock_get):
        """Test fetching findings for a project."""
        self.client.access_token = "test-token"
        
        # Mock last scan response
        mock_scan_response = Mock()
        mock_scan_response.ok = True
        mock_scan_response.json.return_value = {
            "12345": {
                "id": "scan-123",
                "status": "Completed"
            }
        }
        
        # Mock findings response
        mock_findings_response = Mock()
        mock_findings_response.ok = True
        mock_findings_response.json.return_value = {
            "totalCount": 2,
            "results": [
                {
                    "similarityID": "sim-001",
                    "severity": "HIGH",
                    "queryName": "SQL_Injection",
                    "cweID": 89,
                    "group": "Security",
                    "nodes": [
                        {
                            "fileName": "/app/login.py",
                            "line": "45",
                            "column": "12"
                        }
                    ]
                },
                {
                    "similarityID": "sim-002", 
                    "severity": "MEDIUM",
                    "queryName": "XSS",
                    "cweID": 79,
                    "group": "Security",
                    "nodes": []
                }
            ]
        }
        
        mock_get.side_effect = [mock_scan_response, mock_findings_response]
        
        scan_id, findings = self.client.get_findings_for_project("12345", ["HIGH", "MEDIUM"])
        
        self.assertEqual(scan_id, "scan-123")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["queryName"], "SQL_Injection")
    
    def test_process_findings_to_records(self):
        """Test processing raw findings into records."""
        findings = [
            {
                "similarityID": "sim-001",
                "severity": "HIGH",
                "queryName": "SQL_Injection",
                "cweID": 89,
                "group": "Security",
                "languageName": "Python",
                "nodes": [
                    {
                        "fileName": "/app/login.py",
                        "line": "45",
                        "column": "12",
                        "nodeID": 1,
                        "domType": "source"
                    },
                    {
                        "fileName": "/app/login.py",
                        "line": "50",
                        "column": "8",
                        "nodeID": 2,
                        "domType": "sink"
                    }
                ]
            }
        ]
        
        triage_records, detailed_records = self.client.process_findings_to_records(findings)
        
        self.assertEqual(len(triage_records), 1)
        self.assertEqual(len(detailed_records), 1)
        
        # Check triage record
        self.assertEqual(triage_records[0]["severity"], "HIGH")
        self.assertEqual(triage_records[0]["triaged"], "no")
        self.assertTrue(len(triage_records[0]["findingId"]) == 16)
        
        # Check detailed record
        self.assertEqual(detailed_records[0]["queryName"], "SQL_Injection")
        self.assertEqual(detailed_records[0]["cweID"], 89)
        self.assertEqual(len(detailed_records[0]["dataflow"]), 2)


if __name__ == "__main__":
    unittest.main()