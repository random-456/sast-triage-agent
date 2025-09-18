"""Tests for HTML report generator."""

import os
import tempfile
import unittest
from pathlib import Path

from sast_triage.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test cases for ReportGenerator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.report_gen = ReportGenerator(
            output_dir=self.test_dir,
            project_id="TEST-123",
            scan_id="SCAN-456",
            base_url="https://checkmarx.example.com",
            branch="main"
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_initialize_report(self):
        """Test report initialization."""
        self.report_gen.initialize_report(total_findings=5)
        
        # Report path should have timestamp format
        report_files = list(Path(self.test_dir).glob("*_triage_report_*.html"))
        self.assertEqual(len(report_files), 1)
        report_path = report_files[0]
        
        # Check content
        with open(report_path, 'r') as f:
            content = f.read()
        
        self.assertIn("TEST-123", content)
        self.assertIn("SAST Triage Report", content)
        self.assertIn("Total Findings Analyzed", content)
        self.assertIn("5", content)
        # Check for links
        self.assertIn("https://checkmarx.example.com/projects/TEST-123", content)
        self.assertIn("SCAN-456", content)
        self.assertIn("https://checkmarx.example.com/sast-results/TEST-123/SCAN-456", content)
        # Check for branch display
        self.assertIn("Branch:", content)
        self.assertIn("main", content)
    
    def test_add_finding(self):
        """Test adding a finding to report."""
        self.report_gen.initialize_report(total_findings=1)
        
        finding_details = {
            "findingId": "test-001",
            "severity": "HIGH",
            "queryName": "SQL_Injection",
            "cweID": 89,
            "dataflow": [
                {
                    "fileName": "/app/test.py",
                    "line": "10",
                    "method": "get_user",
                    "name": "user_input"
                },
                {
                    "fileName": "/app/test.py",
                    "line": "15",
                    "method": "execute_query",
                    "name": "sql_query"
                }
            ]
        }
        
        assessment = {
            "assessment_result": "CONFIRMED",
            "assessment_confidence": 0.95,
            "assessment_justification": "Direct SQL injection vulnerability"
        }
        
        self.report_gen.add_finding(
            finding_details=finding_details,
            assessment=assessment,
            current=1,
            total=1
        )
        
        # Get the generated report file
        report_files = list(Path(self.test_dir).glob("*_triage_report_*.html"))
        self.assertEqual(len(report_files), 1)
        report_path = report_files[0]
        with open(report_path, 'r') as f:
            content = f.read()
        
        # Check finding content
        self.assertIn("SQL_Injection", content)
        self.assertIn("HIGH", content)
        self.assertIn("CONFIRMED", content)
        self.assertIn("95.0% confidence", content)
        self.assertIn("test-001", content)
        
        # Check progress bar is hidden when complete
        self.assertIn('id="progress-container" class="hidden"', content)
    
    def test_severity_classes(self):
        """Test severity badge styling."""
        classes = self.report_gen._get_severity_classes("HIGH")
        self.assertIn("bg-red-600", classes)
        
        classes = self.report_gen._get_severity_classes("MEDIUM")
        self.assertIn("bg-orange-500", classes)
        
        classes = self.report_gen._get_severity_classes("LOW")
        self.assertIn("bg-yellow-500", classes)
    
    def test_result_classes(self):
        """Test assessment result styling."""
        classes = self.report_gen._get_result_classes("CONFIRMED")
        self.assertIn("text-red-600", classes)
        
        classes = self.report_gen._get_result_classes("NOT_EXPLOITABLE")
        self.assertIn("text-green-600", classes)
        
        classes = self.report_gen._get_result_classes("REFUSED")
        self.assertIn("text-amber-600", classes)
    
    def test_format_dataflow(self):
        """Test dataflow formatting."""
        dataflow = [
            {
                "fileName": "/src/app.py",
                "line": "100",
                "method": "handle_request",
                "name": "user_data"
            },
            {
                "fileName": "/src/db.py",
                "line": "50",
                "method": "execute",
                "name": "query"
            }
        ]
        
        html = self.report_gen._format_dataflow(dataflow)
        
        # Check source and sink labels
        self.assertIn("SOURCE", html)
        self.assertIn("SINK", html)
        
        # Check file paths (relative)
        self.assertIn("src/app.py", html)
        self.assertIn("src/db.py", html)
        
        # Check line numbers
        self.assertIn("100", html)
        self.assertIn("50", html)
    
    def test_not_exploitable_styling(self):
        """Test NOT_EXPLOITABLE findings get grayscale class."""
        self.report_gen.initialize_report(total_findings=1)
        
        finding_details = {
            "findingId": "test-002",
            "severity": "MEDIUM",
            "queryName": "XSS",
            "dataflow": []
        }
        
        assessment = {
            "assessment_result": "NOT_EXPLOITABLE",
            "assessment_confidence": 0.8,
            "assessment_justification": "Input is properly sanitized"
        }
        
        self.report_gen.add_finding(
            finding_details=finding_details,
            assessment=assessment,
            current=1,
            total=1
        )
        
        # Get the generated report file
        report_files = list(Path(self.test_dir).glob("*_triage_report_*.html"))
        self.assertEqual(len(report_files), 1)
        report_path = report_files[0]
        with open(report_path, 'r') as f:
            content = f.read()
        
        # Check for grayscale class
        self.assertIn("not-exploitable", content)
        self.assertIn("NOT EXPLOITABLE", content)


if __name__ == "__main__":
    unittest.main()