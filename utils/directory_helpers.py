import os
import shutil
import stat
import logging

from config import DEFAULT_OUTPUT_DIR

class DirectoryHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def setup_directories(self, output_dir: str = DEFAULT_OUTPUT_DIR):
        """
        [DEPRECATED] This method is no longer used.
        Session directories are managed by PathManager.
        Output directory is no longer needed for CLI.

        Args:
            output_dir: Output directory (ignored)
        """
        pass

    # Handler below needed to remove .git readonly files
    @classmethod
    def handle_remove_readonly(self, func, path, exc_info):
        """
        Error handler for shutil.rmtree.

        If the error is due to a read-only file, it changes the file's permission
        and tries to delete it again. Otherwise, it re-raises the error.
        """
        # Check if the error is a PermissionError
        if not isinstance(exc_info[1], PermissionError):
            raise exc_info[1]

        # Change the file to be writable and retry the deletion
        os.chmod(path, stat.S_IWRITE)
        func(path)