"""
Session storage service for managing JSON-based session persistence
"""
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
import logging
from pathlib import Path
import random
import string

from config import WEB_SESSIONS_DIR, MAX_SESSION_HISTORY
from web_ui.models.session_models import SessionData, SessionMetadata, FindingData
from web_ui.middleware.security import SecurityValidator

logger = logging.getLogger(__name__)

INDEX_FILE = os.path.join(WEB_SESSIONS_DIR, "sessions_index.json")


class SessionStorage:
    """Manages JSON file storage for analysis sessions"""

    def __init__(self):
        self._ensure_directory()

    def _ensure_directory(self):
        """Ensure sessions directory exists"""
        os.makedirs(WEB_SESSIONS_DIR, exist_ok=True)
        if not os.path.exists(INDEX_FILE):
            self._save_index({"sessions": [], "last_updated": datetime.now().isoformat()})

    def _load_index(self) -> Dict:
        """Load sessions index"""
        try:
            with open(INDEX_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading index: {e}")
            return {"sessions": [], "last_updated": datetime.now().isoformat()}

    def _save_index(self, index_data: Dict):
        """Save sessions index"""
        try:
            index_data["last_updated"] = datetime.now().isoformat()
            with open(INDEX_FILE, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving index: {e}")

    def _get_session_file_path(self, session_id: str) -> str:
        """
        Get safe file path for session.

        Args:
            session_id: Session ID

        Returns:
            Absolute file path

        Raises:
            ValueError: If session ID is invalid or path traversal detected
        """
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        base_dir = os.path.abspath(WEB_SESSIONS_DIR)
        file_path = os.path.join(base_dir, f"{session_id}.json")

        # Path traversal check
        if not file_path.startswith(base_dir):
            raise ValueError("Invalid session ID - path traversal detected")

        return file_path

    def generate_session_id(self) -> str:
        """
        Generate a new session ID.

        Returns:
            Session ID in format YYYYMMDD_HHMMSS_{random_6chars}
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{timestamp}_{random_chars}"

    def create_session(
        self,
        project_name: str,
        project_id: str,
        scan_id: str,
        branch: str,
        github_url: str,
        checkmarx_base_url: str,
        findings: List[Dict],
        severity_filters: List[str],
        status_filters: List[str],
        model_name: str = "gemini-2.5-pro"
    ) -> str:
        """
        Create a new analysis session.

        Args:
            project_name: Checkmarx project name
            project_id: Checkmarx project ID
            scan_id: Checkmarx scan ID
            branch: Git branch
            github_url: GitHub repository URL
            checkmarx_base_url: Checkmarx instance base URL
            findings: List of findings from Checkmarx
            severity_filters: Severity filters applied
            status_filters: Status filters applied
            model_name: AI model name

        Returns:
            Generated session ID
        """
        session_id = self.generate_session_id()

        # Convert findings to FindingData models
        finding_models = []
        for finding in findings:
            finding_models.append(FindingData(**finding))

        # Create session data
        session_data = SessionData(
            session_id=session_id,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            status="created",
            metadata=SessionMetadata(
                project_name=project_name,
                project_id=project_id,
                scan_id=scan_id,
                branch=branch,
                github_url=github_url,
                checkmarx_base_url=checkmarx_base_url,
                model_name=model_name,
                severity_filters=severity_filters,
                status_filters=status_filters
            ),
            findings=finding_models
        )

        # Update statistics
        session_data.statistics.total_findings = len(findings)
        session_data.statistics.pending_count = len(findings)

        # Save session file
        self.save_session(session_data.model_dump())

        # Update index
        self._add_to_index(session_data.model_dump())

        logger.info(f"Created session {session_id} with {len(findings)} findings")
        return session_id

    def save_session(self, session_data: Dict):
        """
        Save session data to file.

        Args:
            session_data: Session data dictionary
        """
        session_id = session_data["session_id"]
        file_path = self._get_session_file_path(session_id)

        session_data["updated_at"] = datetime.now().isoformat()

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving session {session_id}: {e}")
            raise

    def load_session(self, session_id: str) -> Optional[Dict]:
        """
        Load session data from file.

        Args:
            session_id: Session ID

        Returns:
            Session data dictionary or None if not found
        """
        file_path = self._get_session_file_path(session_id)

        if not os.path.exists(file_path):
            logger.warning(f"Session {session_id} not found")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading session {session_id}: {e}")
            return None

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session ID

        Returns:
            True if deleted successfully, False otherwise
        """
        file_path = self._get_session_file_path(session_id)

        try:
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove from index
            index = self._load_index()
            index["sessions"] = [s for s in index["sessions"] if s["session_id"] != session_id]
            self._save_index(index)

            logger.info(f"Deleted session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False

    def list_sessions(self, limit: int = MAX_SESSION_HISTORY) -> List[Dict]:
        """
        List all sessions (from index).

        Args:
            limit: Maximum number of sessions to return

        Returns:
            List of session summaries
        """
        index = self._load_index()
        sessions = index.get("sessions", [])

        # Sort by created_at descending (latest first)
        sessions.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return sessions[:limit]

    def _add_to_index(self, session_data: Dict):
        """
        Add session to index.

        Args:
            session_data: Complete session data
        """
        index = self._load_index()

        # Create summary for index
        summary = {
            "session_id": session_data["session_id"],
            "project_name": session_data["metadata"]["project_name"],
            "branch": session_data["metadata"]["branch"],
            "created_at": session_data["created_at"],
            "total_findings": session_data["statistics"]["total_findings"],
            "analyzed_count": session_data["statistics"]["analyzed_count"],
            "confirmed_count": session_data["statistics"]["confirmed_count"],
            "not_exploitable_count": session_data["statistics"]["not_exploitable_count"],
            "refused_count": session_data["statistics"]["refused_count"],
            "status": session_data["status"]
        }

        # Add to beginning
        index["sessions"].insert(0, summary)

        # Trim to max size
        if len(index["sessions"]) > MAX_SESSION_HISTORY:
            index["sessions"] = index["sessions"][:MAX_SESSION_HISTORY]

        self._save_index(index)

    def update_index_entry(self, session_id: str):
        """
        Update index entry after session modification.

        Args:
            session_id: Session ID
        """
        session_data = self.load_session(session_id)
        if not session_data:
            return

        index = self._load_index()

        # Find and update entry
        for i, entry in enumerate(index["sessions"]):
            if entry["session_id"] == session_id:
                index["sessions"][i] = {
                    "session_id": session_data["session_id"],
                    "project_name": session_data["metadata"]["project_name"],
                    "branch": session_data["metadata"]["branch"],
                    "created_at": session_data["created_at"],
                    "total_findings": session_data["statistics"]["total_findings"],
                    "analyzed_count": session_data["statistics"]["analyzed_count"],
                    "confirmed_count": session_data["statistics"]["confirmed_count"],
                    "not_exploitable_count": session_data["statistics"]["not_exploitable_count"],
                    "refused_count": session_data["statistics"]["refused_count"],
                    "status": session_data["status"]
                }
                break

        self._save_index(index)
