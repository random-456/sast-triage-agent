#!/usr/bin/env python3
"""
SAST Triage Agent CLI - Fetches findings from Checkmarx One and runs analysis.

Usage:
    python run_triage.py run PROJECT_NAME [OPTIONS]
    python run_triage.py interactive [OPTIONS]
"""

import asyncio
import logging
import os
import sys
import traceback
from typing import List, Optional

import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import CERTIFICATES_CRT_FILE

# Set SSL Certificate for corporate network
os.environ["REQUESTS_CA_BUNDLE"] = CERTIFICATES_CRT_FILE
os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"] = CERTIFICATES_CRT_FILE

from sast_triage.agent import SASTTriageAgent
from sast_triage.preprocessing.obfuscation import obfuscate_codebase
from sast_triage.preprocessing.secret_masking import mask_secrets
from sast_triage.tracing import (
    initialize_tracing,
    is_tracing_enabled,
    wait_for_trace_review,
)
from utils.checkmarx_helpers import CheckmarxClient
from utils.click_helpers import CommaList
from utils.directory_helpers import DirectoryHelpers
from utils.findings_helpers import FindingsHelpers
from utils.generic_logging import setup_logging
from utils.git_helpers import GitHelpers
from utils.banner import display_banner

from config import (
    CODEBASE_DIR,
    DEFAULT_BRANCH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEVERITIES,
    DEFAULT_STATES,
    DEFAULT_TRIAGE_MODEL,
    TEMP_DIR,
    APP_NAME,
)


async def _run_triage_analysis(
    model_name: str,
    output_dir: str,
    project_name: Optional[str] = None,
    project_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    checkmarx_base_url: Optional[str] = None,
    branch: Optional[str] = None,
    repo_url: Optional[str] = None,
    obfuscation_report=None,
    masking_report=None,
) -> int:
    """
    Run the triage analysis on the fetched data.

    Args:
        model_name: AI model name for Vertex AI
        output_dir: Directory for output files
        project_name: Project name for reporting
        project_id: Project identifier for reporting
        scan_id: Scan identifier for reporting
        checkmarx_base_url: Checkmarx base URL for report links
        branch: Git branch being analyzed
        repo_url: Repository URL for logging context
        obfuscation_report: ObfuscationReport from preprocessing
        masking_report: MaskingReport from preprocessing

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    logger = logging.getLogger("run_triage_analysis")

    try:
        vertex_project = os.getenv("PROJECT_ID")
        vertex_location = os.getenv("DEFAULT_LOCATION")

        if not vertex_project:
            logger.error(
                "PROJECT_ID environment variable is required "
                "for Vertex AI"
            )
            return 1

        logger.info(f"Using Vertex AI project: {vertex_project}")
        logger.info(f"Using location: {vertex_location}")
        logger.info(f"Using model: {model_name}")

        agent = SASTTriageAgent(
            project=vertex_project,
            location=vertex_location,
            model_name=model_name,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            checkmarx_base_url=checkmarx_base_url,
            branch=branch,
            repo_url=repo_url,
            output_dir=output_dir,
        )

        # Log preprocessing reports in the session log
        if obfuscation_report or masking_report:
            agent.agent_logger.log_preprocessing(
                obfuscation_report=obfuscation_report,
                masking_report=masking_report,
            )

        await agent.process_all_findings(output_dir)
        logger.info("Analysis complete!")
        return 0

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        traceback.print_exc()
        return 1


def filter_findings_by_state(
    findings: list[dict],
    state_list: list[str],
) -> list[dict]:
    """
    Filter findings by Checkmarx state (client-side).

    Args:
        findings: Raw findings from the Checkmarx API
        state_list: Allowed states (e.g. ["TO_VERIFY", "CONFIRMED"])

    Returns:
        Filtered list of findings whose state matches
    """
    if not state_list:
        return findings
    state_set = {s.upper() for s in state_list}
    return [f for f in findings if f.get("state", "").upper() in state_set]


def execute_triage(
    project_name: str,
    model_name: str,
    severity_list: list[str],
    state_list: list[str],
    branch: str,
    output_dir: str,
    gitleaks_report: str,
    keep_temp: bool,
    finding_hashes: Optional[List[str]],
    interactive: bool = False,
) -> None:
    """
    Shared triage execution logic used by both run and interactive commands.

    Args:
        project_name: Checkmarx project name
        model_name: AI model for analysis
        severity_list: Severities to filter by
        state_list: Checkmarx states to filter by
        branch: Git branch to analyze
        output_dir: Output directory path
        gitleaks_report: Path to Gitleaks CSV or "none"
        keep_temp: Whether to preserve temp directory
        finding_hashes: Specific finding hashes to target, or None
        interactive: Whether to show interactive preprocessing confirmation
    """
    logger = logging.getLogger("run_triage")

    base_url = os.getenv("BASE_URL")
    refresh_token = os.getenv("REFRESH_TOKEN")

    if not all([base_url, refresh_token]):
        logger.error("Missing required environment variables")
        logger.error(
            "Please ensure the following are set in your .env file:\n"
            "  - BASE_URL: Checkmarx One instance URL\n"
            "  - REFRESH_TOKEN: Your refresh token"
        )
        sys.exit(1)

    logger.info(f"Project Name: {project_name}")

    if finding_hashes:
        severity_list = []
        state_list = []
        logger.info(
            f"Finding Hashes: {', '.join(finding_hashes)} "
            "(fetching all severities and states)"
        )
    else:
        logger.info(f"Severities: {','.join(severity_list)}")
        logger.info(f"States: {','.join(state_list)}")

    logger.info(f"Target branch: {branch}")

    try:
        DirectoryHelpers.setup_directories(output_dir, keep_temp)

        logger.info("Initializing CheckmarxClient")
        client = CheckmarxClient(base_url, refresh_token)

        project_id = client.get_project_id_by_name(project_name)
        if not project_id:
            logger.error(f"Could not find project with name '{project_name}'")
            logger.error(
                "Please verify the project name is correct and you have access to it."
            )
            sys.exit(1)

        repo_url = client.get_project_details(project_id)

        scan_id, findings = client.get_findings_for_project(
            project_id, severity_list, branch
        )

        # Apply client-side state filtering (unless bypassed by finding_hashes)
        if not finding_hashes and state_list:
            original_count = len(findings)
            findings = filter_findings_by_state(findings, state_list)
            logger.info(
                f"State filter: {original_count} -> {len(findings)} findings"
            )

        if not findings:
            logger.error(
                "No findings found for the specified project and filters."
            )
            sys.exit(1)

        if finding_hashes:
            logger.info(
                f"Filtering for findings with hashes: {', '.join(finding_hashes)}"
            )
            original_count = len(findings)
            findings = [
                f for f in findings
                if f.get("data", {}).get("resultHash") in finding_hashes
            ]

            if len(findings) != len(finding_hashes):
                logger.error(
                    f"Could not find all findings with provided hashes "
                    f"in the {original_count} findings fetched for the project."
                )
                sys.exit(1)

            logger.info("Found matching findings.")

        triage_records, detailed_records = client.process_findings_to_records(
            findings
        )
        FindingsHelpers.save_findings_data(triage_records, detailed_records)

        obfuscation_report = None
        masking_report = None

        if repo_url:
            clone_success = GitHelpers.clone_repository(repo_url)
            if not clone_success:
                logger.warning(
                    "Repository cloning failed, continuing with analysis..."
                )
            else:
                logger.info("Obfuscating sensitive elements in codebase...")
                obfuscation_report = obfuscate_codebase(CODEBASE_DIR)
                logger.info(
                    f"Obfuscation complete: "
                    f"{obfuscation_report.total_replacements} replacements "
                    f"in {obfuscation_report.total_files_modified} files"
                )
                if obfuscation_report.replacements_by_type:
                    breakdown = ", ".join(
                        f"{k}: {v}"
                        for k, v in obfuscation_report.replacements_by_type.items()
                    )
                    logger.info(f"Obfuscation breakdown: {breakdown}")

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
                        "No Gitleaks report provided (--gitleaks-report none)"
                    )

                if interactive:
                    from sast_triage.interactive import (
                        display_preprocessing_summary,
                    )

                    if not display_preprocessing_summary(
                        obfuscation_report, masking_report
                    ):
                        click.echo("Triage cancelled.")
                        sys.exit(0)
        else:
            logger.warning(
                "No repository URL found, continuing without codebase."
            )

        exit_code = asyncio.run(
            _run_triage_analysis(
                model_name,
                output_dir,
                project_name,
                project_id,
                scan_id,
                base_url,
                branch,
                repo_url=repo_url,
                obfuscation_report=obfuscation_report,
                masking_report=masking_report,
            )
        )

        wait_for_trace_review()
        sys.exit(exit_code)

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)


def _validate_gitleaks_report(
    ctx: click.Context, param: click.Parameter, value: str
) -> str:
    """
    Click callback that validates --gitleaks-report early.

    Accepts 'none' (case-insensitive) or a path to an existing file.
    """
    if value is None:
        return value
    if value.lower() == "none":
        return value
    if not os.path.isfile(value):
        raise click.BadParameter(
            f"File not found: {os.path.abspath(value)}"
        )
    return value


@click.group()
def cli():
    """SAST Triage Agent - Automated triage of Checkmarx SAST findings."""
    pass


@cli.command()
@click.argument("project_name")
@click.option(
    "--model",
    "model_name",
    default=DEFAULT_TRIAGE_MODEL,
    help="AI Model used for analysis",
)
@click.option(
    "--findings",
    "finding_hashes",
    type=CommaList(),
    help="Comma-separated result hashes of specific findings to analyze",
)
@click.option(
    "--severities",
    default=",".join(DEFAULT_SEVERITIES),
    show_default=True,
    help="Comma-separated list of severities",
)
@click.option(
    "--states",
    default=",".join(DEFAULT_STATES),
    show_default=True,
    help="Comma-separated list of Checkmarx states to include",
)
@click.option(
    "--branch",
    default=DEFAULT_BRANCH,
    help="Git branch to analyze",
)
@click.option(
    "--gitleaks-report",
    required=True,
    callback=_validate_gitleaks_report,
    is_eager=False,
    expose_value=True,
    help="Local path to Gitleaks CSV report, or 'none' to skip",
)
@click.option(
    "--output",
    "output_dir",
    default=DEFAULT_OUTPUT_DIR,
    help="Output directory",
)
@click.option(
    "--keep-temp",
    is_flag=True,
    help=f"Whether to keep {TEMP_DIR} or not",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--trace",
    is_flag=True,
    help="Enable Phoenix tracing (UI at localhost:6006)",
)
def run(
    project_name: str,
    model_name: str,
    severities: str,
    states: str,
    branch: str,
    output_dir: str,
    gitleaks_report: str,
    keep_temp: bool,
    finding_hashes: List,
    verbose: bool,
    trace: bool,
) -> None:
    """
    Run triage in non-interactive mode.

    PROJECT_NAME: The Checkmarx project name to analyze.
    """
    display_banner(APP_NAME)
    setup_logging(logging.DEBUG) if verbose else setup_logging(logging.INFO)

    if trace or is_tracing_enabled():
        initialize_tracing()

    severity_list = [s.strip().upper() for s in severities.split(",")]
    state_list = [s.strip().upper() for s in states.split(",")]

    execute_triage(
        project_name=project_name,
        model_name=model_name,
        severity_list=severity_list,
        state_list=state_list,
        branch=branch,
        output_dir=output_dir,
        gitleaks_report=gitleaks_report,
        keep_temp=keep_temp,
        finding_hashes=finding_hashes,
        interactive=False,
    )


@cli.command()
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--trace",
    is_flag=True,
    help="Enable Phoenix tracing (UI at localhost:6006)",
)
def interactive(verbose: bool, trace: bool) -> None:
    """Run triage in interactive mode with guided prompts."""
    display_banner(APP_NAME)
    setup_logging(logging.DEBUG) if verbose else setup_logging(logging.INFO)

    if trace or is_tracing_enabled():
        initialize_tracing()

    from sast_triage.interactive import (
        display_config_summary,
        prompt_project_config,
    )

    config = prompt_project_config()
    if not display_config_summary(config):
        click.echo("Triage cancelled.")
        sys.exit(0)

    severity_list = [s.strip().upper() for s in config["severities"]]
    state_list = [s.strip().upper() for s in config["states"]]

    execute_triage(
        project_name=config["project_name"],
        model_name=config["model_name"],
        severity_list=severity_list,
        state_list=state_list,
        branch=config["branch"],
        output_dir=config["output_dir"],
        gitleaks_report=config["gitleaks_report"],
        keep_temp=False,
        finding_hashes=config["finding_hashes"],
        interactive=True,
    )


if __name__ == "__main__":
    cli()
