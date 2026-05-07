"""Tests for GitHelpers.clone_repository and GITHUB_TOKENS parsing."""

import base64
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.git_helpers import GitHelpers, parse_host_tokens


def _expected_basic_header(token: str) -> str:
    creds = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return f"http.extraHeader=Authorization: Basic {creds}"


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
    def test_no_host_tokens_omits_extraheader(self, tmp_path, captured_cmd):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "https://github.com/foo/bar.git", target_dir=str(target)
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert "extraHeader" not in " ".join(cmd)
        assert cmd[:2] == ["git", "clone"]

    def test_host_match_injects_basic_header(self, tmp_path, captured_cmd):
        target = tmp_path / "repo"
        token = "ghp_secret123"
        ok = GitHelpers.clone_repository(
            "https://github.com/foo/bar.git",
            target_dir=str(target),
            host_tokens={"github.com": token},
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert cmd[0] == "git"
        assert cmd[1] == "-c"
        assert cmd[2] == _expected_basic_header(token)
        assert cmd[3] == "clone"
        # Raw token must not appear anywhere in argv (only base64-wrapped).
        assert all(token not in part for part in cmd)

    def test_host_miss_omits_header(self, tmp_path, captured_cmd, caplog):
        target = tmp_path / "repo"
        with caplog.at_level(logging.INFO, logger="utils.git_helpers"):
            ok = GitHelpers.clone_repository(
                "https://gitlab.com/foo/bar.git",
                target_dir=str(target),
                host_tokens={"github.com": "ghp_secret123"},
            )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert all("ghp_secret123" not in part for part in cmd)
        assert "extraHeader" not in " ".join(cmd)
        assert any(
            "No GITHUB_TOKENS entry for host 'gitlab.com'" in r.message
            for r in caplog.records
        )

    def test_uppercase_host_matches_lowercase_map_key(
        self, tmp_path, captured_cmd
    ):
        target = tmp_path / "repo"
        token = "ghp_secret123"
        ok = GitHelpers.clone_repository(
            "https://GitHub.com/foo/bar.git",
            target_dir=str(target),
            host_tokens={"github.com": token},
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert _expected_basic_header(token) in cmd

    def test_multiple_hosts_pick_correct_token(self, tmp_path, captured_cmd):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "https://ghe.example.com/foo/bar.git",
            target_dir=str(target),
            host_tokens={
                "github.com": "ghp_aaa",
                "ghe.example.com": "ghp_bbb",
            },
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert _expected_basic_header("ghp_bbb") in cmd
        assert all("ghp_aaa" not in part for part in cmd)
        assert all("ghp_bbb" not in part for part in cmd)

    def test_ssh_url_does_not_inject_header(self, tmp_path, captured_cmd):
        target = tmp_path / "repo"
        ok = GitHelpers.clone_repository(
            "ssh://git@github.com/foo/bar.git",
            target_dir=str(target),
            host_tokens={"github.com": "ghp_secret123"},
        )
        assert ok is True
        cmd = captured_cmd["cmd"]
        assert all("ghp_secret123" not in part for part in cmd)
        assert "extraHeader" not in " ".join(cmd)


class TestCloneRepositoryErrorRedaction:
    def test_token_redacted_from_logged_stderr(self, tmp_path, caplog):
        target = tmp_path / "repo"
        token = "ghp_supersecret"
        leaking_stderr = "fatal: bad credential ghp_supersecret in header"

        def fake_run(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(
                returncode=128, cmd=cmd, stderr=leaking_stderr
            )

        with patch("utils.git_helpers.subprocess.run", side_effect=fake_run), \
             caplog.at_level(logging.ERROR, logger="utils.git_helpers"):
            ok = GitHelpers.clone_repository(
                "https://github.com/foo/bar.git",
                target_dir=str(target),
                host_tokens={"github.com": token},
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


class TestParseHostTokens:
    def test_none_returns_empty_dict(self):
        assert parse_host_tokens(None) == {}

    def test_empty_string_returns_empty_dict(self):
        assert parse_host_tokens("") == {}

    def test_single_pair(self):
        assert parse_host_tokens("github.com=ghp_abc") == {"github.com": "ghp_abc"}

    def test_multiple_pairs(self):
        result = parse_host_tokens(
            "github.com=ghp_abc,ghe.example.com=ghp_xyz"
        )
        assert result == {
            "github.com": "ghp_abc",
            "ghe.example.com": "ghp_xyz",
        }

    def test_lowercases_host_keys(self):
        assert parse_host_tokens("GitHub.COM=ghp_abc") == {"github.com": "ghp_abc"}

    def test_strips_whitespace(self):
        result = parse_host_tokens("  github.com = ghp_abc , ghe.x.com = ghp_y ")
        assert result == {"github.com": "ghp_abc", "ghe.x.com": "ghp_y"}

    def test_skips_malformed_entries(self, caplog):
        with caplog.at_level(logging.WARNING, logger="utils.git_helpers"):
            result = parse_host_tokens("github.com=ghp_abc,broken,=,host=,=tok")
        assert result == {"github.com": "ghp_abc"}
        assert any("malformed" in r.message.lower() for r in caplog.records)
