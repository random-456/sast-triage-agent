import os
import shutil
import stat
import logging

from config import TEMP_DIR
from utils.path_helpers import io_safe

class DirectoryHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def setup_directories(self, output_dir: str, keep_temp_dir: bool = False):
        """
        Clean and create temp directory + create output directory.
        """
        if not keep_temp_dir and os.path.isdir(TEMP_DIR):
            self.logger.info(f"Cleaning {TEMP_DIR} directory...")
            # io_safe applies the Win32 \\?\ long-path prefix so rmtree can
            # walk nested cloned repos that breach MAX_PATH; without it the
            # walk fails with FileNotFoundError on a previous run's leftovers.
            shutil.rmtree(io_safe(TEMP_DIR), onerror=self.handle_remove_readonly)

        os.makedirs(TEMP_DIR, exist_ok=keep_temp_dir)
        os.makedirs(output_dir, exist_ok=True)

        self.logger.info("Directories set up successfully")

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