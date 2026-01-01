"""
Security middleware for input validation and sanitization
"""
import re
import html
from typing import List

from utils.validation import SESSION_ID_PATTERN, validate_session_id as _validate_session_id

# Validation patterns (SESSION_ID_PATTERN imported from utils.validation)
PROJECT_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
BRANCH_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._/-]+$')
FINDING_HASH_PATTERN = re.compile(r'^[a-zA-Z0-9+/=_-]+$')  # Base64 chars: +, /, =

# Whitelists
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_STATES = {"TO_VERIFY", "CONFIRMED", "NOT_EXPLOITABLE",
                  "PROPOSED_NOT_EXPLOITABLE", "URGENT"}
ALLOWED_MODELS = {"gemini-2.5-pro", "gemini-2.5-flash", "gemini-1.5-pro"}


class SecurityValidator:
    """Centralized security validation for all inputs"""

    @staticmethod
    def validate_project_name(name: str) -> str:
        """
        Validate project name against allowed pattern.

        Args:
            name: Project name to validate

        Returns:
            Validated project name

        Raises:
            ValueError: If validation fails
        """
        if not name or len(name) > 255:
            raise ValueError("Project name must be 1-255 characters")
        if not PROJECT_NAME_PATTERN.match(name):
            raise ValueError(
                "Project name contains invalid characters (allowed: a-z, A-Z, 0-9, ., -, _)"
            )
        return name

    @staticmethod
    def validate_branch_name(branch: str) -> str:
        """
        Validate branch name.

        Args:
            branch: Branch name to validate

        Returns:
            Validated branch name

        Raises:
            ValueError: If validation fails
        """
        if not branch or len(branch) > 255:
            raise ValueError("Branch name must be 1-255 characters")
        if not BRANCH_NAME_PATTERN.match(branch):
            raise ValueError("Branch name contains invalid characters")
        return branch

    @staticmethod
    def validate_session_id(session_id: str) -> str:
        """
        Validate session ID format to prevent path traversal attacks.

        Wrapper around utils.validation.validate_session_id for consistency.

        Args:
            session_id: Session ID to validate

        Returns:
            Validated session ID

        Raises:
            ValueError: If validation fails
        """
        return _validate_session_id(session_id)

    @staticmethod
    def validate_severities(severities: List[str]) -> List[str]:
        """
        Validate severity list.

        Args:
            severities: List of severities to validate

        Returns:
            Validated severity list (uppercased)

        Raises:
            ValueError: If any severity is invalid
        """
        upper_severities = [s.upper() for s in severities]
        invalid = set(upper_severities) - ALLOWED_SEVERITIES
        if invalid:
            raise ValueError(
                f"Invalid severities: {invalid}. Allowed: {ALLOWED_SEVERITIES}"
            )
        return upper_severities

    @staticmethod
    def validate_states(states: List[str]) -> List[str]:
        """
        Validate state list.

        Args:
            states: List of states to validate

        Returns:
            Validated state list (uppercased)

        Raises:
            ValueError: If any state is invalid
        """
        upper_states = [s.upper() for s in states]
        invalid = set(upper_states) - ALLOWED_STATES
        if invalid:
            raise ValueError(
                f"Invalid states: {invalid}. Allowed: {ALLOWED_STATES}"
            )
        return upper_states

    @staticmethod
    def validate_model_name(model: str) -> str:
        """
        Validate model name.

        Args:
            model: Model name to validate

        Returns:
            Validated model name

        Raises:
            ValueError: If model is invalid
        """
        if model not in ALLOWED_MODELS:
            raise ValueError(f"Invalid model. Allowed: {ALLOWED_MODELS}")
        return model

    @staticmethod
    def validate_finding_hash(hash_value: str) -> str:
        """
        Validate finding hash (base64 format).

        Args:
            hash_value: Finding hash to validate

        Returns:
            Validated finding hash

        Raises:
            ValueError: If hash is invalid
        """
        if not FINDING_HASH_PATTERN.match(hash_value):
            raise ValueError(
                "Invalid finding hash format (must be base64: alphanumeric, +, /, =)"
            )
        if len(hash_value) > 128:
            raise ValueError("Finding hash too long")
        return hash_value

    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Sanitize text for HTML output (escape special chars).

        Args:
            text: Text to sanitize

        Returns:
            HTML-escaped text
        """
        return html.escape(text) if text else ""
