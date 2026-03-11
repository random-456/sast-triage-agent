"""Tests for Feature 5: Checkmarx API enhancement, search tool improvement, and bug fix."""

import os
import csv
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from utils.checkmarx_helpers import CheckmarxClient
from utils.findings_helpers import FindingsHelpers
from sast_triage.agent_tools import search_in_files


class TestProcessFindingsNewFields(unittest.TestCase):
    """Test that process_findings_to_records extracts description and state."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = CheckmarxClient(
            "https://test.checkmarx.net", "token", ca_cert_path=None
        )

    def test_finding_details_include_description(self):
        """Verify description field is present in detailed records."""
        findings = [
            {
                "type": "sast",
                "id": "hash-001",
                "state": "TO_VERIFY",
                "severity": "HIGH",
                "description": "SQL injection found in login.py at line 45.",
                "data": {
                    "queryName": "SQL_Injection",
                    "group": "Security",
                    "resultHash": "hash-001",
                    "languageName": "Python",
                    "nodes": [
                        {"fileName": "/app/login.py", "line": 45, "domType": "source"}
                    ],
                },
                "vulnerabilityDetails": {"cweId": 89},
            }
        ]

        triage_records, detailed_records = self.client.process_findings_to_records(
            findings
        )

        self.assertEqual(len(detailed_records), 1)
        self.assertIn("description", detailed_records[0])
        self.assertEqual(
            detailed_records[0]["description"],
            "SQL injection found in login.py at line 45.",
        )

    def test_triage_records_include_state(self):
        """Verify state field is present in triage records."""
        findings = [
            {
                "type": "sast",
                "id": "hash-001",
                "state": "TO_VERIFY",
                "severity": "HIGH",
                "description": "Some description",
                "data": {
                    "queryName": "SQL_Injection",
                    "group": "Security",
                    "resultHash": "hash-001",
                    "languageName": "Python",
                    "nodes": [],
                },
                "vulnerabilityDetails": {"cweId": 89},
            }
        ]

        triage_records, _ = self.client.process_findings_to_records(findings)

        self.assertEqual(len(triage_records), 1)
        self.assertIn("state", triage_records[0])
        self.assertEqual(triage_records[0]["state"], "TO_VERIFY")

    def test_detailed_record_extracts_nested_fields(self):
        """Verify fields are correctly extracted from the /api/results structure."""
        findings = [
            {
                "type": "sast",
                "id": "abc123",
                "state": "CONFIRMED",
                "severity": "MEDIUM",
                "description": "XSS vulnerability",
                "data": {
                    "queryName": "XSS_Reflected",
                    "group": "JS_Security",
                    "resultHash": "abc123",
                    "languageName": "JavaScript",
                    "nodes": [{"fileName": "/app.js", "line": 10}],
                },
                "vulnerabilityDetails": {"cweId": 79},
            }
        ]

        _, detailed_records = self.client.process_findings_to_records(findings)
        record = detailed_records[0]

        self.assertEqual(record["resultHash"], "abc123")
        self.assertEqual(record["category"], "JS_Security")
        self.assertEqual(record["cweID"], 79)
        self.assertEqual(record["languageName"], "JavaScript")
        self.assertEqual(record["queryName"], "XSS_Reflected")
        self.assertEqual(record["severity"], "MEDIUM")
        self.assertEqual(record["description"], "XSS vulnerability")
        self.assertEqual(len(record["dataflow"]), 1)


class TestCsvStateColumn(unittest.TestCase):
    """Test that FindingsHelpers writes the state column to CSV."""

    def test_csv_includes_state_column(self):
        """Verify saved CSV includes the state column."""
        triage_records = [
            {
                "resultHash": "hash-001",
                "severity": "HIGH",
                "state": "TO_VERIFY",
                "triaged": "no",
            },
            {
                "resultHash": "hash-002",
                "severity": "LOW",
                "state": "CONFIRMED",
                "triaged": "no",
            },
        ]
        detailed_records = [
            {"resultHash": "hash-001", "description": "desc1"},
            {"resultHash": "hash-002", "description": "desc2"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "triage_list.csv")
            json_path = os.path.join(tmpdir, "findings_details.json")

            with patch("utils.findings_helpers.FINDINGS_DIR", tmpdir), \
                 patch("utils.findings_helpers.FINDINGS_CSV_FILE", csv_path), \
                 patch("utils.findings_helpers.FINDINGS_JSON_FILE", json_path):
                FindingsHelpers.save_findings_data(triage_records, detailed_records)

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertIn("state", reader.fieldnames)
            self.assertEqual(rows[0]["state"], "TO_VERIFY")
            self.assertEqual(rows[1]["state"], "CONFIRMED")


class TestSearchInFilesMultipleExtensions(unittest.TestCase):
    """Test search_in_files with multiple extensions and wildcard."""

    def setUp(self):
        """Set up test codebase path."""
        self.test_codebase = os.path.join(
            os.path.dirname(__file__), "test_data", "codebase"
        )

    def test_search_multiple_extensions(self):
        """Search with 'js,py' finds files of both types."""
        with patch("sast_triage.agent_tools.CODEBASE_DIR", self.test_codebase):
            result = search_in_files.invoke(
                {"pattern": "SELECT.*FROM", "file_extensions": "js,py"}
            )

        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["matches_found"], 2)

        matched_files = {r["file"] for r in result["results"]}
        has_js = any(f.endswith(".js") for f in matched_files)
        has_py = any(f.endswith(".py") for f in matched_files)
        self.assertTrue(has_js, "Expected at least one .js match")
        self.assertTrue(has_py, "Expected at least one .py match")

    def test_search_all_files(self):
        """Search with '*' finds files regardless of extension."""
        with patch("sast_triage.agent_tools.CODEBASE_DIR", self.test_codebase):
            result = search_in_files.invoke(
                {"pattern": "SELECT.*FROM", "file_extensions": "*"}
            )

        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["matches_found"], 2)

    def test_search_results_limit(self):
        """Verify results are capped at MAX_SEARCH_RESULTS (50)."""
        with patch("sast_triage.agent_tools.CODEBASE_DIR", self.test_codebase), \
             patch("sast_triage.agent_tools.MAX_SEARCH_RESULTS", 1):
            result = search_in_files.invoke(
                {"pattern": ".*", "file_extensions": "*"}
            )

        self.assertNotIn("error", result)
        self.assertEqual(result["matches_found"], 1)

    def test_search_single_extension_still_works(self):
        """Ensure backward compatibility with a single extension."""
        with patch("sast_triage.agent_tools.CODEBASE_DIR", self.test_codebase):
            result = search_in_files.invoke(
                {"pattern": "SELECT.*FROM", "file_extensions": "js"}
            )

        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["matches_found"], 1)

    def test_search_default_all_files(self):
        """Default file_extensions should be '*' (all files)."""
        with patch("sast_triage.agent_tools.CODEBASE_DIR", self.test_codebase):
            result = search_in_files.invoke({"pattern": "SELECT.*FROM"})

        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["matches_found"], 2)


class TestCsvStatusUpdateBugFix(unittest.TestCase):
    """Test that update_csv_status uses the correct default CSV path."""

    def test_csv_status_update_default_path(self):
        """Verify update_csv_status default parameter is FINDINGS_CSV_FILE."""
        from sast_triage.agent import SASTTriageAgent
        import inspect

        sig = inspect.signature(SASTTriageAgent.update_csv_status)
        csv_path_param = sig.parameters["csv_path"]

        from config import FINDINGS_CSV_FILE
        self.assertEqual(csv_path_param.default, FINDINGS_CSV_FILE)

    def test_csv_status_update_works_with_state_column(self):
        """Verify update_csv_status works when CSV has state column."""
        from sast_triage.agent import SASTTriageAgent

        with patch("sast_triage.agent.ChatVertexAI") as mock_chat:
            mock_llm = Mock()
            mock_llm.bind_tools = Mock(return_value=mock_llm)
            mock_chat.return_value = mock_llm

            agent = SASTTriageAgent(
                project="test",
                location="test",
                model_name="test-model",
                temperature=0.1,
            )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=["resultHash", "severity", "state", "triaged"]
            )
            writer.writeheader()
            writer.writerow(
                {
                    "resultHash": "hash-001",
                    "severity": "HIGH",
                    "state": "TO_VERIFY",
                    "triaged": "no",
                }
            )
            csv_path = f.name

        try:
            agent.update_csv_status("hash-001", csv_path)

            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(rows[0]["triaged"], "yes")
            self.assertEqual(rows[0]["state"], "TO_VERIFY")
        finally:
            os.unlink(csv_path)


if __name__ == "__main__":
    unittest.main()
