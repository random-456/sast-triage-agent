"""
Checkmarx service for web UI - wraps the existing CheckmarxClient
"""
import os
import logging
from typing import List, Tuple, Optional, Dict
from dotenv import load_dotenv

from utils.checkmarx_helpers import CheckmarxClient

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class CheckmarxService:
    """Service for interacting with Checkmarx API"""

    def __init__(self):
        """Initialize Checkmarx client"""
        self.base_url = os.getenv("BASE_URL")
        self.refresh_token = os.getenv("REFRESH_TOKEN")

        if not self.base_url or not self.refresh_token:
            raise ValueError(
                "Checkmarx credentials not found. "
                "Please set BASE_URL and REFRESH_TOKEN in .env file"
            )

        self.client = CheckmarxClient(
            base_url=self.base_url,
            refresh_token=self.refresh_token
        )

    def search_project(self, project_name: str) -> Optional[Dict]:
        """
        Search for a project by name.

        Args:
            project_name: Project name to search for

        Returns:
            Project info or None if not found
        """
        try:
            project_id = self.client.get_project_id_by_name(project_name)
            if not project_id:
                return None

            # Get project details
            project_details = self.client.get_project_details(project_id)
            if not project_details:
                return None

            return {
                "id": project_id,
                "name": project_name,
                "repoUrl": project_details.get("repoUrl", "")
            }

        except Exception as e:
            logger.error(f"Error searching for project {project_name}: {e}")
            return None

    def fetch_findings(
        self,
        project_name: str,
        branch: str,
        severity_filters: List[str],
        state_filters: List[str]
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], List[Dict]]:
        """
        Fetch findings from Checkmarx for a project.

        Args:
            project_name: Project name
            branch: Git branch
            severity_filters: List of severities to filter
            state_filters: List of states to filter

        Returns:
            Tuple of (project_id, scan_id, github_url, checkmarx_base_url, findings)

        Raises:
            ValueError: If project not found or no findings
        """
        try:
            # Get project ID
            project_id = self.client.get_project_id_by_name(project_name)
            if not project_id:
                raise ValueError(f"Project '{project_name}' not found in Checkmarx")

            logger.info(f"Found project ID: {project_id}")

            # Get project details for GitHub URL
            project_details = self.client.get_project_details(project_id)
            github_url = project_details.get("repoUrl", "") if project_details else ""

            # Get findings
            scan_id, findings = self.client.get_findings_for_project(
                project_id=project_id,
                severities=severity_filters,
                branch=branch,
                states=state_filters
            )

            if not scan_id:
                raise ValueError(f"No scans found for project '{project_name}' on branch '{branch}'")

            logger.info(f"Retrieved {len(findings)} findings from scan {scan_id}")

            # Process findings to add Checkmarx URLs
            processed_findings = []
            for finding in findings:
                # Add Checkmarx URL for the finding
                result_hash = finding.get("resultHash", "")
                checkmarx_url = self._generate_checkmarx_url(project_id, scan_id, result_hash)

                processed_findings.append({
                    **finding,
                    "checkmarx_url": checkmarx_url
                })

            return project_id, scan_id, github_url, self.base_url, processed_findings

        except Exception as e:
            logger.error(f"Error fetching findings: {e}")
            raise

    def _generate_checkmarx_url(
        self,
        project_id: str,
        scan_id: str,
        result_hash: str
    ) -> str:
        """
        Generate Checkmarx finding URL.

        Args:
            project_id: Project ID
            scan_id: Scan ID
            result_hash: Finding result hash

        Returns:
            Checkmarx URL for the finding
        """
        from urllib.parse import quote

        # Based on existing report_helpers.py pattern
        return f"{self.base_url}/results/{project_id}/sast?id={quote(result_hash)}"

    def get_project_details(self, project_id: str) -> Optional[Dict]:
        """
        Get detailed information about a project.

        Args:
            project_id: Project ID

        Returns:
            Project details or None
        """
        try:
            return self.client.get_project_details(project_id)
        except Exception as e:
            logger.error(f"Error getting project details: {e}")
            return None
