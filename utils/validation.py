"""Shared validation utilities for session IDs and other security-critical inputs."""
import re


# Session ID format: YYYYMMDD_HHMMSS_xxxxxx (20 chars total)
# Example: 20250101_120530_a7f2k9
SESSION_ID_PATTERN = re.compile(r'^\d{8}_\d{6}_[a-zA-Z0-9]{6}$')


def validate_session_id(session_id: str) -> str:
    """
    Validate session ID format to prevent path traversal attacks.

    Args:
        session_id: Session identifier to validate

    Returns:
        The validated session_id (unchanged if valid)

    Raises:
        ValueError: If session_id doesn't match required format

    Security:
        This function is critical for preventing path traversal attacks.
        Session IDs are used to construct filesystem paths, so strict
        validation is required to ensure they contain only safe characters.
    """
    if not session_id:
        raise ValueError("Session ID cannot be empty")

    if not SESSION_ID_PATTERN.match(session_id):
        raise ValueError(
            f"Invalid session ID format. Expected YYYYMMDD_HHMMSS_xxxxxx, "
            f"got: {session_id[:20]}"  # Truncate to avoid log injection
        )

    return session_id
