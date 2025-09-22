"""Checkmarx One API client for fetching SAST findings."""

import os
from typing import Dict, List, Optional, Tuple

import requests


class CheckmarxClient:
    """Client for interacting with Checkmarx One API."""
    
    def __init__(self, base_url: str, refresh_token: str, client_id: str = "ast-app", ca_cert_path: Optional[str] = None):
        """
        Initialize the Checkmarx API client.
        
        Args:
            base_url: The base URL of the Checkmarx instance
            refresh_token: The refresh token for authentication
            client_id: The client ID for the application
            ca_cert_path: Path to CA certificate file for SSL verification
        """
        self.base_url = base_url.rstrip("/")
        self.refresh_token = refresh_token
        self.client_id = client_id
        # Import here to avoid circular imports
        from sast_triage.config import CHECKMARX_CA_CERT
        self.ca_cert_path = ca_cert_path or CHECKMARX_CA_CERT
        self.access_token = None
    
    @property
    def verify_ssl(self) -> bool | str:
        """
        Determine SSL verification setting.
        
        Returns:
            Path to CA cert file if it exists, otherwise True for default verification
        """
        if self.ca_cert_path and os.path.exists(self.ca_cert_path):
            return self.ca_cert_path
        return True
    
    def refresh_access_token(self) -> str:
        """
        Refresh the access token using the refresh token.
        
        Returns:
            A new access token
            
        Raises:
            requests.exceptions.HTTPError: If token refresh fails
        """
        print("Refreshing access token...")
        from sast_triage.config import CHECKMARX_REALM
        token_url = f"{self.base_url}/auth/realms/{CHECKMARX_REALM}/protocol/openid-connect/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": self.refresh_token
        }
        
        response = requests.post(token_url, data=data, verify=self.verify_ssl)
        response.raise_for_status()
        
        self.access_token = response.json()["access_token"]
        print("Successfully refreshed access token.")
        return self.access_token
    
    def get_project_id_by_name(self, project_name: str) -> Optional[str]:
        """
        Retrieve project ID by project name.
        
        Args:
            project_name: The name of the project
            
        Returns:
            The project ID if found, otherwise None
            
        Raises:
            requests.exceptions.HTTPError: If the request fails
        """
        if not self.access_token:
            self.refresh_access_token()
        
        print(f"Looking up project ID for: {project_name}")
        projects_url = f"{self.base_url}/api/projects"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.access_token}"
        }
        params = {"name": project_name}
        
        try:
            response = requests.get(projects_url, headers=headers, params=params, verify=self.verify_ssl)
            response.raise_for_status()
            projects_data = response.json()
            
            projects = projects_data.get("projects", [])
            if not projects:
                print(f"No project found with name: {project_name}")
                return None
            
            if len(projects) > 1:
                print(f"Warning: Multiple projects found with name '{project_name}', using the first one")
                for i, project in enumerate(projects):
                    print(f"  {i+1}. ID: {project.get('id')}, Name: {project.get('name')}")
            
            project_id = projects[0].get("id")
            if project_id:
                print(f"Found project ID: {project_id}")
                return project_id
            else:
                print("Project ID not found in response")
                return None
                
        except requests.exceptions.HTTPError as e:
            print(f"Could not look up project by name: {e}")
            return None
    
    def get_project_details(self, project_id: str) -> Optional[str]:
        """
        Retrieve project details to find repository URL.
        
        Args:
            project_id: The ID of the project
            
        Returns:
            The repository URL if found, otherwise None
        """
        if not self.access_token:
            self.refresh_access_token()
        
        print(f"\nGetting details for project: {project_id}")
        project_url = f"{self.base_url}/api/projects/{project_id}"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.access_token}"
        }
        
        try:
            response = requests.get(project_url, headers=headers, verify=self.verify_ssl)
            response.raise_for_status()
            project_data = response.json()
            
            repo_url = project_data.get("repoUrl")
            if repo_url:
                print(f"Found repository URL: {repo_url}")
                return repo_url
            else:
                print("Repository URL not found in project details.")
                return None
        except requests.exceptions.HTTPError as e:
            print(f"Could not fetch project details: {e}")
            return None
    
    def get_findings_for_project(
        self, 
        project_id: str, 
        severities: Optional[List[str]] = None,
        branch: Optional[str] = None
    ) -> Tuple[Optional[str], List[Dict]]:
        """
        Retrieve SAST findings from the latest scan of a project.
        
        Args:
            project_id: The ID of the project
            severities: List of severities to filter (e.g., ["HIGH", "MEDIUM"])
            branch: Optional branch name to get latest scan from
            
        Returns:
            A tuple of (scan_id, list of findings)
        """
        if not self.access_token:
            self.refresh_access_token()
        
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Import here to avoid circular imports
        from sast_triage.config import DEFAULT_BRANCH
        
        # Use provided branch or default
        target_branch = branch or DEFAULT_BRANCH
        
        # Find the last scan for the project (with branch)
        print(f"\nGetting last scan for project: {project_id} (branch: {target_branch})")
        last_scans_url = f"{self.base_url}/api/projects/last-scan"
        last_scans_params = {
            "project-ids": project_id,
            "branch": target_branch
        }
        
        response = requests.get(
            last_scans_url, 
            headers=headers, 
            params=last_scans_params, 
            verify=self.verify_ssl
        )
        
        if not response.ok:
            print(f"Error getting last scan: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        last_scans_data = response.json()
        
        # If no scan found for the specific branch, fallback to any latest scan
        if not last_scans_data or project_id not in last_scans_data:
            if branch:  # Only fallback if we were looking for a specific branch
                print(f"No scan found for branch '{target_branch}', falling back to latest scan from any branch")
                last_scans_params = {"project-ids": project_id}  # Remove branch param
                
                response = requests.get(
                    last_scans_url, 
                    headers=headers, 
                    params=last_scans_params, 
                    verify=self.verify_ssl
                )
                
                if not response.ok:
                    print(f"Error getting fallback scan: {response.status_code} - {response.text}")
                    response.raise_for_status()
                
                last_scans_data = response.json()
        
        if not last_scans_data or project_id not in last_scans_data:
            print(f"No scan information found for project ID: {project_id}")
            return None, []
        
        scan_info = last_scans_data[project_id]
        scan_id = scan_info["id"]
        scan_branch = scan_info.get("branch", "unknown")
        print(f"Found scan ID: {scan_id} (branch: {scan_branch})")
        
        # Get all findings for the scan
        all_findings = []
        offset = 0
        limit = 1000  # Max limit per request
        
        print(f"Getting findings for scan {scan_id}...")
        if severities:
            print(f"Filtering by severities: {', '.join(severities)}")
        
        while True:
            findings_url = f"{self.base_url}/api/sast-results"
            findings_params = {
                "scan-id": scan_id,
                "include-nodes": "true",
                "apply-predicates": "true",
                "offset": offset,
                "limit": limit,
                "sort": "+status,-severity,-queryname",
            }
            
            response = requests.get(
                findings_url,
                headers=headers,
                params=findings_params,
                verify=self.verify_ssl
            )
            
            if not response.ok:
                print(f"Error getting findings: {response.status_code} - {response.text}")
                response.raise_for_status()
            
            scan_data = response.json()
            results = scan_data.get("results", [])
            
            if not results:
                break
            
            # Filter by severity if specified
            if severities:
                severity_set = {s.upper() for s in severities}
                filtered_results = [
                    r for r in results 
                    if r.get("severity", "").upper() in severity_set
                ]
                all_findings.extend(filtered_results)
            else:
                all_findings.extend(results)
            
            print(f"Fetched {len(all_findings)} findings...")
            
            if len(results) < limit:
                break
            
            offset += limit
        
        print(f"Total findings retrieved: {len(all_findings)}")
        return scan_id, all_findings
    
    def process_findings_to_records(
        self, 
        findings: List[Dict]
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Process raw findings into triage and detailed records.
        
        Args:
            findings: List of raw finding dictionaries from API
            
        Returns:
            Tuple of (triage_records, detailed_records)
        """
        triage_records = []
        detailed_records = []
        
        for finding in findings:
            nodes = finding.get("nodes", [])
            
            # Use resultHash from Checkmarx as the result hash
            result_hash = finding.get("resultHash", "")
            
            triage_records.append({
                "resultHash": result_hash,
                "severity": finding.get("severity", ""),
                "triaged": "no"
            })
            
            detailed_records.append({
                "resultHash": result_hash,
                "category": finding.get("group", ""),
                "cweID": finding.get("cweID", ""),
                "languageName": finding.get("languageName", ""),
                "queryName": finding.get("queryName", ""),
                "severity": finding.get("severity", ""),
                "dataflow": nodes
            })
        
        return triage_records, detailed_records