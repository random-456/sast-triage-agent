"""Git repository management utilities."""

import os
import subprocess
import logging


class GitHelpers:

    logger = logging.getLogger(__name__)

    @classmethod
    def clone_repository(
        self,
        repo_url: str,
        target_dir: str,
        quiet: bool = True
    ) -> bool:
        """
        Clone a git repository to the specified directory.

        Args:
            repo_url: The URL of the git repository
            target_dir: The target directory for cloning (REQUIRED - use PathManager)
            quiet: Whether to suppress git output

        Returns:
            True if successful, False otherwise
        """
        if not repo_url:
            self.logger.warning("No repository URL provided, skipping clone.")
            return False

        os.makedirs(target_dir, exist_ok=True)

        # Check if directory already exists and has content
        if os.path.isdir(target_dir) and any(os.listdir(target_dir)):
            # Verify it's the CORRECT repository by checking remote URL
            try:
                result = subprocess.run(
                    ["git", "-C", target_dir, "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                existing_url = result.stdout.strip()

                # Normalize URLs for comparison (remove .git suffix, trailing slashes, case-insensitive)
                def normalize_url(url: str) -> str:
                    return url.rstrip('/').removesuffix('.git').lower()

                if normalize_url(existing_url) == normalize_url(repo_url):
                    self.logger.info(f"Repository {repo_url} already cloned at {target_dir}")
                    return True
                else:
                    self.logger.error(
                        f"Directory {target_dir} contains WRONG repository!\n"
                        f"  Found: {existing_url}\n"
                        f"  Expected: {repo_url}"
                    )
                    return False

            except subprocess.CalledProcessError:
                self.logger.error(
                    f"Directory {target_dir} exists but is not a valid git repository"
                )
                return False

        self.logger.info(f"Cloning repository from {repo_url}...")

        try:
            # Prepare git command
            cmd = ["git", "clone", "--depth", "1", repo_url, target_dir]
            if quiet:
                cmd.append("--quiet")

            # Execute git clone
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            self.logger.info("Repository cloned successfully.")
            return True

        except FileNotFoundError:
            self.logger.error("'git' command not found. Please ensure Git is installed.")
            return False

        except subprocess.CalledProcessError as e:
            if "already exists and is not an empty directory" in e.stderr:
                self.logger.error("Directory already contains a repository.")
                return True
            else:
                self.logger.error(f"Failed to clone repository: {e.returncode}")
                if e.stderr:
                    self.logger.error(f"Error details: {e.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Unexpected error while cloning: {e}")
            return False