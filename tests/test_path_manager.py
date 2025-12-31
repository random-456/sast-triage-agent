"""Tests for PathManager security and path traversal prevention."""
import pytest
from utils.path_manager import PathManager


class TestPathManagerSecurity:
    """Test PathManager security against path traversal attacks."""

    def test_path_manager_rejects_path_traversal(self):
        """Test that PathManager rejects path traversal in session_id."""
        path_traversal_attempts = [
            "../../etc/passwd",
            "../../../sensitive_dir",
            "../",
            "..",
            "/etc/passwd",
            "C:\\Windows\\System32",
        ]
        for attack_id in path_traversal_attempts:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                PathManager(session_id=attack_id)

    def test_path_manager_accepts_valid_session_id(self):
        """Test that PathManager accepts valid session IDs."""
        valid_session_id = "20250101_120530_abc123"
        pm = PathManager(session_id=valid_session_id)

        assert pm.session_id == valid_session_id
        assert valid_session_id in pm.base_dir
        assert "codebase" in pm.codebase_dir
        assert "findings" in pm.findings_dir

    def test_path_manager_rejects_empty_session_id(self):
        """Test that PathManager rejects empty session IDs."""
        with pytest.raises(ValueError, match="session_id is required"):
            PathManager(session_id="")

    def test_path_manager_rejects_malformed_session_id(self):
        """Test that PathManager rejects malformed session IDs."""
        malformed_ids = [
            "20250101_120530",  # Missing suffix
            "invalid_session_id",
            "20250101_120530_abc!23",  # Special char
        ]
        for malformed_id in malformed_ids:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                PathManager(session_id=malformed_id)

    def test_path_manager_base_dir_construction(self):
        """Test that base_dir is constructed correctly."""
        session_id = "20250615_143022_z9Y8x7"
        pm = PathManager(session_id=session_id)

        # Verify paths are constructed correctly
        assert pm.base_dir.endswith(session_id)
        assert pm.codebase_dir.endswith(f"{session_id}/codebase")
        assert pm.findings_dir.endswith(f"{session_id}/findings")
        assert pm.findings_json_file.endswith(f"{session_id}/findings/findings_details.json")
