"""Git repository management utilities."""

import os
import subprocess
import logging
from typing import List, Optional
from urllib.parse import urlparse

from config import CODEBASE_DIR

_GITHUB_HOSTS = {"github.com", "www.github.com"}


class GitHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def clone_repository(
        cls,
        repo_url: str,
        target_dir: str = CODEBASE_DIR,
        quiet: bool = True,
        token: Optional[str] = None,
    ) -> bool:
        """
        Clone a git repository to the specified directory.

        Args:
            repo_url: The URL of the git repository
            target_dir: The target directory for cloning
            quiet: Whether to suppress git output
            token: Optional GitHub access token. When provided and the URL
                points to github.com, the token is sent as a Bearer
                Authorization header for the clone invocation only (it is
                never written to .git/config or embedded in the URL).

        Returns:
            True if successful, False otherwise
        """
        if not repo_url:
            cls.logger.warning("No repository URL provided, skipping clone.")
            return False

        os.makedirs(target_dir, exist_ok=True)

        if os.path.isdir(target_dir) and any(os.listdir(target_dir)):
            cls.logger.warning(
                f"Directory {target_dir} already exists and is not empty. "
                "Assuming repository is already cloned."
            )
            return True

        effective_token = token if token and _is_github_url(repo_url) else None
        if token and not effective_token:
            cls.logger.info(
                "GITHUB_TOKEN is set but repo URL is not on github.com — "
                "skipping token auth."
            )
        if effective_token:
            cls.logger.info("Authenticating with GITHUB_TOKEN.")

        cls.logger.info(f"Cloning repository from {repo_url}...")

        cmd = _build_clone_command(repo_url, target_dir, quiet, effective_token)

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            cls.logger.info("Repository cloned successfully.")
            return True

        except FileNotFoundError:
            cls.logger.error(
                "'git' command not found. Please ensure Git is installed."
            )
            return False

        except subprocess.CalledProcessError as e:
            stderr = _redact(e.stderr, effective_token)
            if stderr and "already exists and is not an empty directory" in stderr:
                cls.logger.error("Directory already contains a repository.")
                return True
            cls.logger.error(f"Failed to clone repository: {e.returncode}")
            if stderr:
                cls.logger.error(f"Error details: {stderr}")
            return False

        except Exception as e:
            cls.logger.error(f"Unexpected error while cloning: {_redact(str(e), effective_token)}")
            return False


def _is_github_url(repo_url: str) -> bool:
    host = (urlparse(repo_url).hostname or "").lower()
    return host in _GITHUB_HOSTS


def _build_clone_command(
    repo_url: str,
    target_dir: str,
    quiet: bool,
    token: Optional[str],
) -> List[str]:
    """Build the argv list for `git clone`, optionally with a Bearer auth header.

    The `-c http.extraHeader=...` flag goes before the `clone` subcommand so it
    only applies to this invocation and is not persisted in the cloned repo's
    config.
    """
    cmd: List[str] = ["git"]
    if token:
        cmd += ["-c", f"http.extraHeader=Authorization: Bearer {token}"]
    cmd += ["clone", "--depth", "1", repo_url, target_dir]
    if quiet:
        cmd.append("--quiet")
    return cmd


def _redact(text: Optional[str], token: Optional[str]) -> Optional[str]:
    if not text or not token:
        return text
    return text.replace(token, "***")
