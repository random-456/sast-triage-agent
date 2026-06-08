"""Tests for ``utils.directory_helpers``."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import TEMP_DIR
from utils.directory_helpers import DirectoryHelpers


class TestSetupDirectoriesCleanup:
    """Cleanup must route through ``io_safe`` so Windows ``shutil.rmtree``
    can walk nested cloned trees that breach the 260-char MAX_PATH.

    Without the prefix, leftover ``temp/codebase`` from a previous run causes
    rmtree to abort with FileNotFoundError on the deep paths, even though
    the parent directories list cleanly.
    """

    def test_rmtree_receives_io_safe_form(self):
        """``setup_directories`` passes ``io_safe(TEMP_DIR)`` to ``rmtree``."""
        with patch("utils.directory_helpers.shutil.rmtree") as mock_rmtree, \
             patch("utils.directory_helpers.os.path.isdir", return_value=True), \
             patch("utils.directory_helpers.os.makedirs"), \
             patch(
                 "utils.directory_helpers.io_safe",
                 side_effect=lambda p: f"<io_safe>{p}",
             ) as mock_io_safe:
            DirectoryHelpers.setup_directories("output_dir")

        mock_io_safe.assert_called_once_with(TEMP_DIR)
        args, _ = mock_rmtree.call_args
        assert args[0] == f"<io_safe>{TEMP_DIR}"

    def test_no_cleanup_when_temp_dir_absent(self):
        """If ``TEMP_DIR`` does not exist, rmtree must not be called."""
        with patch("utils.directory_helpers.shutil.rmtree") as mock_rmtree, \
             patch("utils.directory_helpers.os.path.isdir", return_value=False), \
             patch("utils.directory_helpers.os.makedirs"):
            DirectoryHelpers.setup_directories("output_dir")

        mock_rmtree.assert_not_called()

    def test_no_cleanup_when_keep_temp_dir(self):
        """``keep_temp_dir=True`` skips cleanup even when TEMP_DIR exists."""
        with patch("utils.directory_helpers.shutil.rmtree") as mock_rmtree, \
             patch("utils.directory_helpers.os.path.isdir", return_value=True), \
             patch("utils.directory_helpers.os.makedirs"):
            DirectoryHelpers.setup_directories("output_dir", keep_temp_dir=True)

        mock_rmtree.assert_not_called()


class TestTimestampedSubdir:
    """``timestamped_subdir`` groups one run's outputs under a dated folder.

    The directory is created through ``io_safe`` so the extra nesting does not
    push the path past Windows MAX_PATH before the agent starts writing.
    """

    def test_creates_and_returns_timestamped_subdir(self):
        with patch("utils.directory_helpers.os.makedirs") as mock_makedirs, \
             patch(
                 "utils.directory_helpers.io_safe",
                 side_effect=lambda p: f"<io_safe>{p}",
             ), \
             patch("utils.directory_helpers.datetime") as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "20260608_143000"
            result = DirectoryHelpers.timestamped_subdir("out")

        expected = os.path.join("out", "20260608_143000")
        assert result == expected
        mock_makedirs.assert_called_once_with(f"<io_safe>{expected}", exist_ok=True)
