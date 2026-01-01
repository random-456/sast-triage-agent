#!/usr/bin/env python3
"""
SAST Triage Agent CLI - Fetches findings from Checkmarx One and runs analysis
Usage: python run_triage.py PROJECT_NAME [OPTIONS]
"""

import asyncio
import logging
import os
import sys
import traceback
from datetime import datetime
from typing import List

import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import CERTIFICATES_CRT_FILE

# Set SSL certificate for corporate network
os.environ['REQUESTS_CA_BUNDLE'] = CERTIFICATES_CRT_FILE
os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = CERTIFICATES_CRT_FILE

from sast_triage_agent import SASTTriageAgent
from utils.checkmarx_helpers import CheckmarxClient
from utils.git_helpers import GitHelpers
from utils.click_helpers import CommaList
from utils.directory_helpers import DirectoryHelpers
from utils.findings_helpers import FindingsHelpers
from utils.generic_logging import setup_logging
from utils.banner import display_banner
from web_ui.services.session_storage import SessionStorage
from utils.path_manager import PathManager

from config import DEFAULT_SEVERITIES, DEFAULT_BRANCH, DEFAULT_TRIAGE_MODEL, DEFAULT_OUTPUT_DIR, APP_NAME

async def run_triage_analysis(
    model_name: str,
    session_id: str,
    path_manager: PathManager,
    session_storage: SessionStorage,
    project_name: str = None,
    project_id: str = None,
    scan_id: str = None,
    checkmarx_base_url: str = None,
    branch: str = None
) -> int:
    """
    Run triage analysis on all pending findings in the session.
    Updates session.json with results after each finding.

    Args:
        model_name: AI model to use
        session_id: Session identifier
        path_manager: PathManager for session-specific paths
        session_storage: SessionStorage for updating session.json
        project_name: Checkmarx project name
        project_id: Checkmarx project ID
        scan_id: Checkmarx scan ID
        checkmarx_base_url: Checkmarx API base URL
        branch: Git branch name

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    logger = logging.getLogger("run_triage_analysis")

    try:
        # Load session
        session = session_storage.load_session(session_id)
        logger.info(f"Loaded session {session_id}")
        logger.info(f"Session has {len(session['findings'])} findings")

        # Initialize agent (NO output_dir parameter)
        vertex_project = os.getenv("PROJECT_ID")
        vertex_location = os.getenv("DEFAULT_LOCATION", "us-central1")

        if not vertex_project:
            logger.error("PROJECT_ID environment variable is required for Vertex AI")
            return 1

        logger.info(f"Using Vertex AI project: {vertex_project}")
        logger.info(f"Using location: {vertex_location}")
        logger.info(f"Using model: {model_name}")
        logger.info(f"Session ID: {session_id}")
        logger.info(f"Codebase: {path_manager.codebase_dir}")

        agent = SASTTriageAgent(
            project=vertex_project,
            location=vertex_location,
            model_name=model_name,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            checkmarx_base_url=checkmarx_base_url,
            branch=branch,
            path_manager=path_manager
            # NOTE: No output_dir parameter!
        )

        logger.info("Starting analysis of pending findings...")

        # Track statistics
        completed_count = 0
        failed_count = 0

        # Analyze each finding in session
        for finding_data in session["findings"]:
            finding_hash = finding_data["resultHash"]

            # Skip if already analyzed
            if finding_data.get("analysis", {}).get("status") == "completed":
                logger.info(f"Skipping {finding_hash[:8]} - already analyzed")
                completed_count += 1
                continue

            # Mark as in_progress
            finding_data["analysis"]["status"] = "in_progress"
            finding_data["analysis"]["started_at"] = datetime.now().isoformat()
            session_storage.save_session(session)
            logger.info(f"Analyzing {finding_hash[:8]}...")

            try:
                # Run analysis
                decision = await agent.analyze_single_finding(finding_hash)

                # Update with results
                finding_data["analysis"]["status"] = "completed"
                finding_data["analysis"]["completed_at"] = datetime.now().isoformat()
                finding_data["analysis"]["result"] = decision.assessment_result
                finding_data["analysis"]["confidence"] = decision.assessment_confidence
                finding_data["analysis"]["justification"] = decision.assessment_justification

                # Calculate duration
                start_time = datetime.fromisoformat(finding_data["analysis"]["started_at"])
                end_time = datetime.fromisoformat(finding_data["analysis"]["completed_at"])
                finding_data["analysis"]["duration_seconds"] = (end_time - start_time).total_seconds()

                # Get conversation log
                finding_log = agent.agent_logger.get_finding_log(finding_hash)
                if finding_log:
                    finding_data["analysis"]["conversation_log"] = finding_log.get("conversation", [])
                    finding_data["analysis"]["iterations_used"] = finding_log.get("iteration_count", 0)

                completed_count += 1
                logger.info(f"✓ {finding_hash[:8]}: {decision.assessment_result} ({decision.assessment_confidence:.2f})")

            except Exception as e:
                # Mark as failed
                finding_data["analysis"]["status"] = "failed"
                finding_data["analysis"]["completed_at"] = datetime.now().isoformat()
                finding_data["analysis"]["last_action"] = f"Error: {str(e)}"

                failed_count += 1
                logger.error(f"✗ {finding_hash[:8]}: Failed - {str(e)}")

            # Save session after each finding
            session_storage.save_session(session)

        # Update session status and statistics
        session["status"] = "completed"
        session["statistics"] = {
            "total_findings": len(session["findings"]),
            "completed": completed_count,
            "failed": failed_count,
            "pending": len(session["findings"]) - completed_count - failed_count,
            "confirmed": sum(1 for f in session["findings"] if f.get("analysis", {}).get("result") == "CONFIRMED"),
            "not_exploitable": sum(1 for f in session["findings"] if f.get("analysis", {}).get("result") == "NOT_EXPLOITABLE"),
            "refused": sum(1 for f in session["findings"] if f.get("analysis", {}).get("result") == "REFUSED")
        }
        session_storage.save_session(session)

        logger.info(f"Analysis complete: {completed_count} completed, {failed_count} failed")
        logger.info(f"Session results saved to: analysis_sessions/{session_id}/session.json")

        return 0 if failed_count == 0 else 1

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return 1


@click.command()
@click.argument("project_name")
@click.option("--model", "model_name", default=DEFAULT_TRIAGE_MODEL, help="AI Model used for analysis")
@click.option("--findings", "finding_hashes", type=CommaList(), help="Comma-separated hash of a single finding to analyze.")
@click.option("--severities", default=",".join(DEFAULT_SEVERITIES), help="Comma-separated list of severities")
@click.option("--branch", default=DEFAULT_BRANCH,help="Git branch to analyze")
@click.option("--output", "output_dir", default=DEFAULT_OUTPUT_DIR, help="[DEPRECATED - not used] Output directory for legacy reports")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def run_triage(
    project_name: str,
    model_name: str,
    severities: str,
    branch: str,
    output_dir: str,
    finding_hashes: List,
    verbose: bool
) -> None:
    """
    Fetch SAST findings from Checkmarx One and run triage analysis.
    
    PROJECT_NAME: The Checkmarx project name to analyze
    """
    
    display_banner(APP_NAME)
    
    setup_logging(logging.DEBUG) if verbose else setup_logging(logging.INFO)
    logger = logging.getLogger("run_triage")
    
    # Check environment variables
    base_url = os.getenv("BASE_URL")
    refresh_token = os.getenv("REFRESH_TOKEN")
    
    if not all([base_url, refresh_token]):
        logger.error("Missing required environment variables")
        logger.error("""Please ensure the following are set in your .env file:\n
                     - BASE_URL: Checkmarx One instance URL\n
                     - REFRESH_TOKEN: Your refresh token""")
        sys.exit(1)
    
    # Parse severities and branch
    target_branch = branch
    logger.info(f"Project Name: {project_name}")
    
    if finding_hashes:
        # When a specific finding is targeted, ignore severity filters to ensure the finding is fetched.
        severity_list = []
        logger.info(f"Finding Hashes: {', '.join(finding_hashes)} (fetching all severities)")
    else:
        severity_list = [s.strip().upper() for s in severities.split(",")]
        logger.info(f"Severities: {','.join(severity_list)}")
    
    logger.info(f"Target branch: {target_branch}")
    
    try:
        # Initialize Checkmarx client
        logger.info("Initializing CheckmarxClient")
        client = CheckmarxClient(base_url, refresh_token)
        
        # Resolve project name to ID
        project_id = client.get_project_id_by_name(project_name)
        if not project_id:
            logger.error(f"Could not find project with name '{project_name}'")
            logger.error(f"Please verify the project name is correct and you have access to it.")
            sys.exit(1)
        
        # Get project details and repository URL
        repo_url = client.get_project_details(project_id)
        
        # Get findings
        scan_id, findings = client.get_findings_for_project(project_id, severity_list, target_branch)
        
        if not findings:
            logger.error("No findings found for the specified project and severities.")
            sys.exit(1)
        
        # If a specific finding hash is provided, filter the list
        if finding_hashes:
            logger.info(f"Filtering for single finding with hashes: {', '.join(finding_hashes)}")
            original_count = len(findings)
            findings = [f for f in findings if f.get("resultHash") in finding_hashes]
            
            if len(findings) != len(finding_hashes):
                logger.error(f"Could not find all the findings with provided hashes in the {original_count} findings fetched for the project.")
                sys.exit(1)
        
        logger.info(f"Found {len(findings)} matching findings")

        # Create session for CLI analysis
        session_storage = SessionStorage()
        session_id = session_storage.generate_session_id()
        logger.info(f"Session ID: {session_id}")

        # Create PathManager
        path_manager = PathManager(session_id=session_id)
        path_manager.ensure_directories()
        logger.info(f"Session directory: {path_manager.base_dir}")

        # Convert to session findings format
        session_findings = []
        for finding in findings:
            session_findings.append({
                "resultHash": finding.get("resultHash", ""),
                "category": finding.get("group", ""),
                "cweID": str(finding.get("cweID", "")),
                "languageName": finding.get("languageName", ""),
                "queryName": finding.get("queryName", ""),
                "severity": finding.get("severity", ""),
                "state": finding.get("state", ""),
                "dataflow": finding.get("nodes", []),
                "analysis": {
                    "status": "pending",
                    "result": None,
                    "confidence": None,
                    "justification": None,
                    "started_at": None,
                    "completed_at": None,
                    "duration_seconds": None,
                    "conversation_log": [],
                    "iterations_used": 0
                }
            })

        # Create session
        session_storage.create_session(
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            branch=target_branch,
            github_url=repo_url or "",
            checkmarx_base_url=base_url,
            findings=session_findings,
            severity_filters=severity_list,
            status_filters=[],
            model_name=model_name
        )

        # Mark as CLI source
        session = session_storage.load_session(session_id)
        session["metadata"]["source"] = "cli"
        session_storage.save_session(session)
        logger.info(f"Created CLI session with {len(session_findings)} findings")

        # Process findings into detailed records with agent_analyzed field
        detailed_records = client.process_findings_to_records(findings)

        # Save findings data (JSON only) to session-specific directory
        FindingsHelpers.save_findings_data(
            detailed_records,
            findings_dir=path_manager.findings_dir,
            findings_json_file=path_manager.findings_json_file
        )
        logger.info(f"Saved findings to {path_manager.findings_json_file}")

        # Clone repository if URL available to session-specific directory
        if repo_url:
            clone_success = GitHelpers.clone_repository(
                repo_url,
                target_dir=path_manager.codebase_dir
            )
            if not clone_success:
                logger.error(f"Failed to clone repository to {path_manager.codebase_dir}")
                sys.exit(1)
            logger.info(f"Cloned repository to {path_manager.codebase_dir}")
        else:
            logger.warning("No repository URL found, continuing without codebase.")

        # Run triage analysis
        try:
            exit_code = asyncio.run(
                run_triage_analysis(
                    model_name,
                    session_id,
                    path_manager,
                    session_storage,
                    project_name,
                    project_id,
                    scan_id,
                    base_url,
                    target_branch
                )
            )

            logger.info("Analysis complete!")
            logger.info(f"Session results: analysis_sessions/{session_id}/session.json")

        finally:
            # Cleanup only codebase (keep session results)
            logger.info(f"Cleaning up codebase for session {session_id}...")
            try:
                path_manager.cleanup_codebase()
                logger.info("Codebase cleaned up successfully")
                logger.info(f"Session preserved at: analysis_sessions/{session_id}/")
            except Exception as e:
                logger.warning(f"Failed to cleanup session: {e}")
                # Don't fail - results are already saved

        sys.exit(exit_code)
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_triage()