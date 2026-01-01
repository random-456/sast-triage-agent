"""Path management for session-specific directories."""
import os
import logging
from config import ANALYSIS_SESSIONS_DIR
from utils.validation import validate_session_id


logger = logging.getLogger(__name__)


class PathManager:
    """
    Manages file paths for SAST Triage Agent sessions.
    All analyses (CLI and WebUI) use session-specific directories.
    """

    def __init__(self, session_id: str):
        """
        Initialize PathManager for a specific session.

        Args:
            session_id: Session identifier (REQUIRED)

        Raises:
            ValueError: If session_id is not provided, empty, or invalid format
        """
        if not session_id:
            raise ValueError(
                "session_id is required for PathManager. "
                "Both CLI and WebUI must provide a session ID."
            )

        # Validate session ID format to prevent path traversal attacks
        validate_session_id(session_id)

        self.session_id = session_id
        self.base_dir = os.path.join(ANALYSIS_SESSIONS_DIR, session_id)

        # Derived paths
        self.codebase_dir = os.path.join(self.base_dir, "codebase")
        self.findings_dir = os.path.join(self.base_dir, "findings")
        self.findings_json_file = os.path.join(
            self.findings_dir, "findings_details.json"
        )

    def ensure_directories(self):
        """Create necessary session directories."""
        os.makedirs(self.codebase_dir, exist_ok=True)
        os.makedirs(self.findings_dir, exist_ok=True)

    def cleanup_all(self):
        """
        Remove entire session directory including all contents.

        Used by CLI to cleanup after extracting results to output/.
        WebUI should use SessionStorage.delete_session() instead.
        """
        if os.path.exists(self.base_dir):
            import shutil
            from utils.directory_helpers import DirectoryHelpers

            shutil.rmtree(
                self.base_dir,
                onerror=DirectoryHelpers.handle_remove_readonly
            )

    def cleanup_codebase(self):
        """
        Remove only the codebase directory (for CLI after analysis).
        Keeps session.json and findings/ directory with analysis results.

        Used by CLI to free disk space while preserving analysis results.
        WebUI should NOT call this - sessions include codebase for incremental analysis.
        """
        if os.path.exists(self.codebase_dir):
            import shutil
            from utils.directory_helpers import DirectoryHelpers

            logger.info(f"Removing codebase directory: {self.codebase_dir}")
            shutil.rmtree(
                self.codebase_dir,
                onerror=DirectoryHelpers.handle_remove_readonly
            )
            logger.info("Codebase directory removed successfully")
