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
from typing import List

import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import CERTIFICATES_CRT_FILE

# Set SSL Certificate for corporate network
os.environ['REQUESTS_CA_BUNDLE'] = CERTIFICATES_CRT_FILE
os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = CERTIFICATES_CRT_FILE

from sast_triage.agent import SASTTriageAgent
from sast_triage.preprocessing.obfuscation import obfuscate_codebase
from sast_triage.preprocessing.secret_masking import mask_secrets
from utils.checkmarx_helpers import CheckmarxClient
from utils.git_helpers import GitHelpers
from utils.click_helpers import CommaList
from utils.directory_helpers import DirectoryHelpers
from utils.findings_helpers import FindingsHelpers
from utils.generic_logging import setup_logging
from utils.banner import display_banner

from config import (
    CODEBASE_DIR,
    DEFAULT_SEVERITIES,
    DEFAULT_BRANCH,
    DEFAULT_TRIAGE_MODEL,
    TEMP_DIR,
    DEFAULT_OUTPUT_DIR,
    APP_NAME,
)



async def run_triage_analysis(model_name: str, output_dir: str, project_name: str = None, project_id: str = None,
                             scan_id: str = None, checkmarx_base_url: str = None,
                             branch: str = None) -> int:
    """
    Run the triage analysis on the fetched data.

    Args:
        project_name: Project name for reporting
        project_id: Project identifier for reporting
        scan_id: Scan identifier for reporting
        checkmarx_base_url: Checkmarx base URL for report links
        branch: Git branch being analyzed

    Returns:
        Exit code (0 for success, 1 for failure)
    """

    logger = logging.getLogger("run_triage_analysis")

    try:
        # Get Vertex AI configuration
        vertex_project = os.getenv("PROJECT_ID")
        vertex_location = os.getenv("DEFAULT_LOCATION")

        if not vertex_project:
            logger.error("PROJECT_ID environment variable is required for Vertex AI")
            return 1

        logger.info(f"Using Vertex AI project: {vertex_project}")
        logger.info(f"Using location: {vertex_location}")
        logger.info(f"Using model: {model_name}")

        # Initialize and run the agent
        agent = SASTTriageAgent(
            project=vertex_project,
            location=vertex_location,
            model_name=model_name,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            checkmarx_base_url=checkmarx_base_url,
            branch=branch,
            output_dir=output_dir
        )

        results = await agent.process_all_findings(output_dir)

        logger.info("Analysis complete!")

        return 0

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        traceback.print_exc()
        return 1


@click.command()
@click.argument("project_name")
@click.option("--model", "model_name", default=DEFAULT_TRIAGE_MODEL, help="AI Model used for analysis")
@click.option("--findings", "finding_hashes", type=CommaList(), help="The result hash of a single finding to analyze.")
@click.option("--severities", default=",".join(DEFAULT_SEVERITIES), help="Comma-separated list of severities")
@click.option("--branch", default=DEFAULT_BRANCH, help="Git branch to analyze")
@click.option("--output", "output_dir", default=DEFAULT_OUTPUT_DIR, help="Output directory")
@click.option(
    "--gitleaks-report",
    required=True,
    help="Path or URL to Gitleaks CSV report, or 'none' if no report exists",
)
@click.option("--keep-temp", is_flag=True, help=f"Whether to keep {TEMP_DIR} or not")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def run_triage(
    project_name: str,
    model_name: str,
    severities: str,
    branch: str,
    output_dir: str,
    gitleaks_report: str,
    keep_temp: bool,
    finding_hashes: List,
    verbose: bool,
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
        # Setup temp and output directories
        DirectoryHelpers.setup_directories(output_dir, keep_temp)

        # Initialize Checkmarx client
        logger.info("Initializing CheckmarxClient")
        client = CheckmarxClient(base_url, refresh_token)

        # Resolve project name to ID
        project_id = client.get_project_id_by_name(project_name)
        if not project_id:
            logger.error(f"Could not find project with name '{project_name}'")
            logger.error("Please verify the project name is correct and you have access to it.")
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

            logger.info("Found matching findings.")

        # Process findings
        triage_records, detailed_records = client.process_findings_to_records(findings)

        # Save findings data
        FindingsHelpers.save_findings_data(triage_records, detailed_records)

        # Clone repository if URL available
        if repo_url:
            clone_success = GitHelpers.clone_repository(repo_url)
            if not clone_success:
                logger.warning("Repository cloning failed, continuing with analysis...")
            else:
                # Mandatory: obfuscate sensitive elements
                logger.info("Obfuscating sensitive elements in codebase...")
                obfuscation_report = obfuscate_codebase(CODEBASE_DIR)
                logger.info(
                    f"Obfuscation complete: {obfuscation_report.total_replacements} "
                    f"replacements in {obfuscation_report.total_files_modified} files"
                )
                if obfuscation_report.replacements_by_type:
                    breakdown = ", ".join(
                        f"{k}: {v}"
                        for k, v in obfuscation_report.replacements_by_type.items()
                    )
                    logger.info(f"Obfuscation breakdown: {breakdown}")

                # Mandatory: mask secrets from Gitleaks report
                if gitleaks_report.lower() != "none":
                    logger.info("Masking secrets from Gitleaks report...")
                    masking_report = mask_secrets(
                        CODEBASE_DIR, gitleaks_report
                    )
                    logger.info(
                        f"Secret masking complete: "
                        f"{masking_report.total_secrets_masked} secrets "
                        f"masked in {masking_report.files_modified} files"
                    )
                else:
                    logger.info(
                        "No Gitleaks report provided "
                        "(--gitleaks-report none)"
                    )
        else:
            logger.warning("No repository URL found, continuing without codebase.")

        # Run triage analysis
        exit_code = asyncio.run(run_triage_analysis(model_name, output_dir, project_name, project_id, scan_id, base_url, target_branch))

        sys.exit(exit_code)

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_triage()