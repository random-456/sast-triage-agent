"""Git repository management utilities."""

import base64
import os
import subprocess
import logging
from typing import Dict, List, Mapping, Optional
from urllib.parse import urlparse

from config import CODEBASE_DIR


class GitHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def clone_repository(
        cls,
        repo_url: str,
        target_dir: str = CODEBASE_DIR,
        quiet: bool = True,
        host_tokens: Optional[Mapping[str, str]] = None,
    ) -> bool:
        """
        Clone a git repository to the specified directory.

        Args:
            repo_url: The URL of the git repository
            target_dir: The target directory for cloning
            quiet: Whether to suppress git output
            host_tokens: Optional mapping of lowercase hostname -> access token.
                If the URL's host is in the map, the matching token is sent as
                an HTTP Basic Authorization header (with the conventional
                "x-access-token" username) for this clone invocation only — it
                is not written to .git/config or embedded in the URL. Basic is
                used because GitHub Enterprise Server does not reliably accept
                Bearer for git-over-HTTPS, while github.com accepts both.
                Hosts not in the map fall back to the local git CLI credentials.

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

        token = _resolve_token(repo_url, host_tokens, cls.logger)

        cls.logger.info(f"Cloning repository from {repo_url}...")

        cmd = _build_clone_command(repo_url, target_dir, quiet, token)

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
            stderr = _redact(e.stderr, token)
            if stderr and "already exists and is not an empty directory" in stderr:
                cls.logger.error("Directory already contains a repository.")
                return True
            cls.logger.error(f"Failed to clone repository: {e.returncode}")
            if stderr:
                cls.logger.error(f"Error details: {stderr}")
            return False

        except Exception as e:
            cls.logger.error(
                f"Unexpected error while cloning: {_redact(str(e), token)}"
            )
            return False


def _resolve_token(
    repo_url: str,
    host_tokens: Optional[Mapping[str, str]],
    logger: logging.Logger,
) -> Optional[str]:
    """Return the token for the URL's host, or None if there is no match.

    Hostname comparison is case-insensitive. Only HTTPS URLs are eligible —
    Basic-header auth has no effect over SSH/git protocols. If a host entry
    exists but the URL scheme is not HTTPS, a warning is emitted so the user
    is not left wondering why the configured token did not apply.
    """
    if not host_tokens:
        return None
    parsed = urlparse(repo_url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    configured = host_tokens.get(host)

    if configured and scheme == "https":
        logger.info(
            f"Authenticating with token from GITHUB_TOKENS for host '{host}'."
        )
        return configured
    if configured:
        logger.warning(
            f"GITHUB_TOKENS has an entry for host '{host}' but URL scheme is "
            f"'{scheme}' — token only applies to https URLs; falling back to "
            "local git credentials."
        )
        return None
    logger.info(
        f"No GITHUB_TOKENS entry for host '{host}' — "
        "using local git credentials."
    )
    return None


def _build_clone_command(
    repo_url: str,
    target_dir: str,
    quiet: bool,
    token: Optional[str],
) -> List[str]:
    """Build the argv list for `git clone`, optionally with a Basic auth header.

    The `-c http.extraHeader=...` flag goes before the `clone` subcommand so it
    only applies to this invocation and is not persisted in the cloned repo's
    config. The token is base64-encoded as `x-access-token:<token>` — the
    pattern used by GitHub Apps and GitHub Actions, which works for classic
    PATs, fine-grained PATs, and App installation tokens against both
    github.com and GitHub Enterprise Server.
    """
    cmd: List[str] = ["git"]
    if token:
        creds = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraHeader=Authorization: Basic {creds}"]
    cmd += ["clone"]
    if quiet:
        cmd.append("--quiet")
    cmd += ["--depth", "1", repo_url, target_dir]
    return cmd


def _redact(text: Optional[str], token: Optional[str]) -> Optional[str]:
    if not text or not token:
        return text
    return text.replace(token, "***")


def parse_host_tokens(raw: Optional[str]) -> Dict[str, str]:
    """Parse a GITHUB_TOKENS env value into a {lowercase_host: token} dict.

    Format: "host1=token1,host2=token2". Whitespace around entries is trimmed.
    Empty input or None returns an empty dict. Malformed entries (no '=', or
    missing host/token) are skipped with a warning so a single typo does not
    silently strip every token.
    """
    if not raw:
        return {}
    result: Dict[str, str] = {}
    logger = logging.getLogger(__name__)
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        host, sep, token = entry.partition("=")
        host = host.strip().lower()
        token = token.strip()
        if not sep or not host or not token:
            logger.warning(
                "Ignoring malformed GITHUB_TOKENS entry "
                "(expected 'host=token')."
            )
            continue
        result[host] = token
    return result
