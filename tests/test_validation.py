"""Tests for session ID validation and path traversal prevention."""
import pytest
from utils.validation import validate_session_id


class TestSessionIDValidation:
    """Test session ID validation against path traversal attacks."""

    def test_valid_session_id(self):
        """Test that valid session IDs pass validation."""
        valid_ids = [
            "20250101_120530_a7f2k9",
            "20241231_235959_AbCd12",
            "19990101_000000_000000",
            "20251231_235959_ABC123",
            "20250615_143022_z9Y8x7",
        ]
        for session_id in valid_ids:
            assert validate_session_id(session_id) == session_id

    def test_path_traversal_attempts(self):
        """Test that path traversal attempts are rejected."""
        attack_ids = [
            "../../../etc/passwd",
            "../../important_dir",
            "../",
            ".",
            "..",
            "....",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "20250101_120530_../../etc",
            "../20250101_120530_abc123",
            "20250101_120530_abc123/..",
            "20250101_120530_abc123/../",
        ]
        for attack_id in attack_ids:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(attack_id)

    def test_empty_session_id(self):
        """Test that empty session IDs are rejected."""
        with pytest.raises(ValueError, match="Session ID cannot be empty"):
            validate_session_id("")

    def test_invalid_formats(self):
        """Test that malformed session IDs are rejected."""
        invalid_ids = [
            "20250101_120530",  # Missing random suffix
            "20250101_120530_",  # Empty suffix
            "20250101_120530_abc",  # Suffix too short
            "20250101_120530_abcdefgh",  # Suffix too long
            "2025-01-01_12:05:30_abc123",  # Wrong separators
            "20250101-120530-abc123",  # Wrong separators
            "abc_def_ghi",  # Not numbers
            "20250101_120530_abc!23",  # Special characters in suffix
            "20250101_120530_abc 23",  # Space in suffix
            "20250101 120530 abc123",  # Spaces instead of underscores
            "20250101/120530/abc123",  # Slashes
            "20250101\\120530\\abc123",  # Backslashes
        ]
        for invalid_id in invalid_ids:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(invalid_id)

    def test_absolute_paths(self):
        """Test that absolute paths are rejected."""
        absolute_paths = [
            "/etc/passwd",
            "/var/log/system.log",
            "C:\\Windows\\System32",
            "D:\\Users\\Admin",
            "/home/user/.ssh/id_rsa",
        ]
        for path in absolute_paths:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(path)

    def test_null_byte_injection(self):
        """Test that null byte injection attempts are rejected."""
        null_byte_ids = [
            "20250101_120530_abc123\x00",
            "20250101_120530_abc123\x00../../etc/passwd",
            "\x0020250101_120530_abc123",
        ]
        for null_id in null_byte_ids:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(null_id)

    def test_unicode_and_special_chars(self):
        """Test that unicode and special characters are rejected."""
        special_ids = [
            "20250101_120530_😀😀😀",
            "20250101_120530_abc@#$",
            "20250101_120530_abc<>?",
            "20250101_120530_abc|;&",
            "20250101_120530_abc\n\r\t",
        ]
        for special_id in special_ids:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(special_id)

    def test_edge_case_dates(self):
        """Test edge case dates are validated correctly."""
        # Valid edge cases
        valid_edge_cases = [
            "00000000_000000_abc123",  # All zeros
            "99999999_999999_abc123",  # Max digits
        ]
        for session_id in valid_edge_cases:
            assert validate_session_id(session_id) == session_id

        # Invalid edge cases
        invalid_edge_cases = [
            "2025010_120530_abc123",  # 7 digits instead of 8
            "202501011_120530_abc123",  # 9 digits instead of 8
            "20250101_12053_abc123",  # 5 digits instead of 6
            "20250101_1205300_abc123",  # 7 digits instead of 6
        ]
        for invalid_id in invalid_edge_cases:
            with pytest.raises(ValueError, match="Invalid session ID format"):
                validate_session_id(invalid_id)

    def test_case_sensitivity(self):
        """Test that alphanumeric suffix accepts both upper and lowercase."""
        mixed_case_ids = [
            "20250101_120530_ABCDEF",  # All uppercase
            "20250101_120530_abcdef",  # All lowercase
            "20250101_120530_AbCdEf",  # Mixed case
            "20250101_120530_123456",  # All numbers
            "20250101_120530_a1B2c3",  # Mixed alphanumeric
        ]
        for session_id in mixed_case_ids:
            assert validate_session_id(session_id) == session_id

    def test_length_validation(self):
        """Test that session IDs must be exactly 21 characters."""
        # Too short
        with pytest.raises(ValueError, match="Invalid session ID format"):
            validate_session_id("20250101_120530_abc12")  # 20 chars

        # Too long
        with pytest.raises(ValueError, match="Invalid session ID format"):
            validate_session_id("20250101_120530_abc1234")  # 22 chars

        # Exactly right
        assert validate_session_id("20250101_120530_abc123") == "20250101_120530_abc123"  # 21 chars
