"""Tests for GitHelpers.clone_repository, focused on token authentication."""

import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.git_helpers import GitHelpers


@pytest.fixture
def captured_cmd():
    """Capture the argv passed to subprocess.run without actually running it."""
    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("utils.git_helpers.subprocess.run", side_effect=fake_run):
        yield captured


class TestCloneRepositoryCommandConstruction:
    def test_no_token_omits_extraheader(self, tmp_path, captured_cmd):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "https://github.com/foo/bar.git", target_dir=str(target)
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert "http.extraHeader=Authorization: Bearer" not in " ".join(cmd)
        assert cmd[:2] == ["git", "clone"]

    def test_github_url_with_token_injects_extraheader(
        self, tmp_path, captured_cmd
    ):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "https://github.com/foo/bar.git",
            target_dir=str(target),
            token="ghp_secret123",
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert cmd[0] == "git"
        assert cmd[1] == "-c"
        assert cmd[2] == "http.extraHeader=Authorization: Bearer ghp_secret123"
        assert cmd[3] == "clone"
        # Token must NOT be embedded in the repo URL.
        assert all("ghp_secret123" not in part for part in cmd[4:])

    def test_non_github_url_with_token_skips_extraheader(
        self, tmp_path, captured_cmd, caplog
    ):
        target = tmp_path / "repo"
        with caplog.at_level(logging.INFO, logger="utils.git_helpers"):
            ok = GitHelpers.clone_repository(
                "https://gitlab.com/foo/bar.git",
                target_dir=str(target),
                token="ghp_secret123",
            )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert all("ghp_secret123" not in part for part in cmd)
        assert "extraHeader" not in " ".join(cmd)
        assert any(
            "not on github.com" in record.message for record in caplog.records
        )

    def test_uppercase_github_host_still_recognized(
        self, tmp_path, captured_cmd
    ):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "https://GitHub.com/foo/bar.git",
            target_dir=str(target),
            token="ghp_secret123",
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert "http.extraHeader=Authorization: Bearer ghp_secret123" in cmd


class TestCloneRepositoryErrorRedaction:
    def test_token_redacted_from_logged_stderr(self, tmp_path, caplog):
        target = tmp_path / "repo"
        token = "ghp_supersecret"
        leaking_stderr = f"fatal: bad credential ghp_supersecret in header"

        def fake_run(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=128, cmd=cmd, stderr=leaking_stderr
            )

        with patch("utils.git_helpers.subprocess.run", side_effect=fake_run), \
             caplog.at_level(logging.ERROR, logger="utils.git_helpers"):
            ok = GitHelpers.clone_repository(
                "https://github.com/foo/bar.git",
                target_dir=str(target),
                token=token,
            )

        assert ok is False
        full_log = "\n".join(record.message for record in caplog.records)
        assert token not in full_log
        assert "***" in full_log


class TestCloneRepositoryDirectoryBypass:
    def test_existing_non_empty_dir_returns_true_without_subprocess(
        self, tmp_path
    ):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "existing.txt").write_text("hello")

        with patch("utils.git_helpers.subprocess.run") as mock_run:
            ok = GitHelpers.clone_repository(
                "https://github.com/foo/bar.git", target_dir=str(target)
            )

        assert ok is True
        mock_run.assert_not_called()

    def test_empty_repo_url_returns_false(self, tmp_path):
        with patch("utils.git_helpers.subprocess.run") as mock_run:
            ok = GitHelpers.clone_repository("", target_dir=str(tmp_path / "x"))
        assert ok is False
        mock_run.assert_not_called()
