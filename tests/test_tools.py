"""
Test suite for SAST Triage Agent tools with focus on security
"""

import os
import sys
import pytest
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sast_triage.tools import (
    validate_safe_path, read_file, list_directory, 
    parse_csv_findings, get_finding_details, search_in_files
)


class TestPathSecurity:
    """Test path validation and security boundaries."""
    
    def test_validate_safe_path_normal(self):
        """Test normal valid paths."""
        base = "/tmp/test"
        
        # Normal file paths should work
        result = validate_safe_path(base, "file.txt")
        assert result == os.path.abspath(os.path.join(base, "file.txt"))
        
        result = validate_safe_path(base, "subdir/file.txt")
        assert result == os.path.abspath(os.path.join(base, "subdir/file.txt"))
    
    def test_validate_safe_path_traversal_attempts(self):
        """Test that path traversal attempts are blocked."""
        base = "/tmp/test"
        
        # Various traversal attempts should raise ValueError
        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            validate_safe_path(base, "../etc/passwd")
        
        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            validate_safe_path(base, "../../etc/passwd")
        
        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            validate_safe_path(base, "../../../../../../../etc/passwd")
        
        with pytest.raises(ValueError, match="Path traversal attempt detected"):
            validate_safe_path(base, "subdir/../../etc/passwd")
    
    def test_validate_safe_path_absolute_paths(self):
        """Test that absolute paths are handled correctly."""
        base = "/tmp/test"
        
        # Absolute paths outside base are actually accepted but resolved to within base
        # This is because we strip leading slashes
        result = validate_safe_path(base, "/etc/passwd")
        # It becomes /tmp/test/etc/passwd
        assert "test" in result
        assert result == os.path.abspath(os.path.join(base, "etc/passwd"))


class TestFileOperations:
    """Test file reading and directory listing with security."""
    
    @pytest.fixture
    def test_codebase(self):
        """Use test data codebase."""
        return os.path.join(os.path.dirname(__file__), "test_data", "codebase")
    
    def test_read_file_normal(self, test_codebase, monkeypatch):
        """Test reading a normal file."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        result = read_file.invoke({"file_path": "vulnerable.js"})
        assert "error" not in result
        assert result["file"] == "vulnerable.js"
        assert result["total_lines"] > 0
        assert any("SQL injection" in line for line in result["content"])
    
    def test_read_file_traversal_blocked(self, test_codebase, monkeypatch):
        """Test that path traversal in read_file is blocked."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        # Try to escape the codebase directory
        result = read_file.invoke({"file_path": "../../../etc/passwd"})
        assert "error" in result
        assert "Invalid path" in result["error"]
        
        result = read_file.invoke({"file_path": "../../requirements.txt"})
        assert "error" in result
        assert "Invalid path" in result["error"]
    
    def test_read_file_nonexistent(self, test_codebase, monkeypatch):
        """Test reading a non-existent file."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        result = read_file.invoke({"file_path": "nonexistent.js"})
        assert "error" in result
        assert "File not found" in result["error"]
    
    def test_list_directory_normal(self, test_codebase, monkeypatch):
        """Test listing a normal directory."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        result = list_directory.invoke({"directory_path": "."})
        assert "error" not in result
        assert result["total_items"] >= 1
        assert any(item["name"] == "vulnerable.js" for item in result["items"])
    
    def test_list_directory_traversal_blocked(self, test_codebase, monkeypatch):
        """Test that path traversal in list_directory is blocked."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        result = list_directory.invoke({"directory_path": "../../"})
        assert "error" in result
        assert "Invalid path" in result["error"]
        
        result = list_directory.invoke({"directory_path": "../../../etc"})
        assert "error" in result
        assert "Invalid path" in result["error"]


class TestFindingOperations:
    """Test finding-related operations."""
    
    @pytest.fixture
    def test_findings_path(self):
        """Path to test findings."""
        return os.path.join(os.path.dirname(__file__), "test_data", "findings")
    
    def test_parse_csv_findings(self, test_findings_path):
        """Test parsing CSV findings."""
        csv_path = os.path.join(test_findings_path, "triage_list.csv")
        findings = parse_csv_findings.invoke({"file_path": csv_path})
        
        assert len(findings) == 2
        assert findings[0]["findingId"] == "test-sql-001"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["triaged"] == "no"
    
    def test_get_finding_details(self, test_findings_path):
        """Test getting finding details from JSON."""
        json_path = os.path.join(test_findings_path, "findings_details.json")
        
        # Test existing finding - use invoke instead of direct call
        details = get_finding_details.invoke({"finding_id": "test-sql-001", "json_path": json_path})
        assert "error" not in details
        assert details["findingId"] == "test-sql-001"
        assert details["cweID"] == 89
        assert len(details["dataflow"]) == 2
        assert details["dataflow"][0]["domType"] == "source"
        assert details["dataflow"][1]["domType"] == "sink"
        
        # Test non-existent finding
        details = get_finding_details.invoke({"finding_id": "nonexistent", "json_path": json_path})
        assert "error" in details
        assert "not found" in details["error"]
    
    @pytest.fixture
    def test_codebase(self):
        """Use test data codebase."""
        return os.path.join(os.path.dirname(__file__), "test_data", "codebase")
    
    def test_search_in_files(self, test_codebase, monkeypatch):
        """Test searching in files."""
        monkeypatch.setattr("sast_triage.tools.CODEBASE_PATH", test_codebase)
        
        # Search for SQL pattern
        result = search_in_files.invoke({"pattern": "SELECT.*FROM", "file_extension": "js"})
        assert "error" not in result
        assert result["matches_found"] >= 2
        
        # Search for non-existent pattern
        result = search_in_files.invoke({"pattern": "NONEXISTENT_PATTERN_XYZ", "file_extension": "js"})
        assert "error" not in result
        assert result["matches_found"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])