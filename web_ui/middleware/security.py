"""
Security middleware for input validation and sanitization
"""
import re
import html
from typing import List
from fastapi import HTTPException, status

# Validation patterns
PROJECT_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
BRANCH_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._/-]+$')
SESSION_ID_PATTERN = re.compile(r'^\d{8}_\d{6}_[a-zA-Z0-9]{6}$')
FINDING_HASH_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')  # Allow alphanumeric, underscore, hyphen

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
            HTTPException: If validation fails
        """
        if not name or len(name) > 255:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project name must be 1-255 characters"
            )
        if not PROJECT_NAME_PATTERN.match(name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project name contains invalid characters (allowed: a-z, A-Z, 0-9, ., -, _)"
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
            HTTPException: If validation fails
        """
        if not branch or len(branch) > 255:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Branch name must be 1-255 characters"
            )
        if not BRANCH_NAME_PATTERN.match(branch):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Branch name contains invalid characters"
            )
        return branch

    @staticmethod
    def validate_session_id(session_id: str) -> str:
        """
        Validate session ID format.

        Args:
            session_id: Session ID to validate

        Returns:
            Validated session ID

        Raises:
            HTTPException: If validation fails
        """
        if not SESSION_ID_PATTERN.match(session_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid session ID format"
            )
        return session_id

    @staticmethod
    def validate_severities(severities: List[str]) -> List[str]:
        """
        Validate severity list.

        Args:
            severities: List of severities to validate

        Returns:
            Validated severity list (uppercased)

        Raises:
            HTTPException: If any severity is invalid
        """
        upper_severities = [s.upper() for s in severities]
        invalid = set(upper_severities) - ALLOWED_SEVERITIES
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severities: {invalid}. Allowed: {ALLOWED_SEVERITIES}"
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
            HTTPException: If any state is invalid
        """
        upper_states = [s.upper() for s in states]
        invalid = set(upper_states) - ALLOWED_STATES
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid states: {invalid}. Allowed: {ALLOWED_STATES}"
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
            HTTPException: If model is invalid
        """
        if model not in ALLOWED_MODELS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid model. Allowed: {ALLOWED_MODELS}"
            )
        return model

    @staticmethod
    def validate_finding_hash(hash_value: str) -> str:
        """
        Validate finding hash (alphanumeric only).

        Args:
            hash_value: Finding hash to validate

        Returns:
            Validated finding hash

        Raises:
            HTTPException: If hash is invalid
        """
        if not FINDING_HASH_PATTERN.match(hash_value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid finding hash format (must be alphanumeric)"
            )
        if len(hash_value) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Finding hash too long"
            )
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
