"""
Interactive mode for SAST Triage Agent.

Provides guided prompts to collect configuration and display preprocessing
summaries before running triage analysis.
"""

import os
import sys
from typing import Optional

import click
import questionary

from config import (
    CHECKMARX_STATES,
    DEFAULT_BRANCH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEVERITIES,
    DEFAULT_STATES,
    DEFAULT_TRIAGE_MODEL,
)
from sast_triage.preprocessing.obfuscation import ObfuscationReport
from sast_triage.preprocessing.secret_masking import MaskingReport


def prompt_project_config() -> dict:
    """
    Collect all triage configuration via interactive prompts.

    Returns:
        Dictionary with keys: project_name, branch, finding_hashes,
        states, severities, model_name, gitleaks_report, output_dir
    """
    click.echo()

    project_name = questionary.text(
        "Checkmarx project name:",
        validate=lambda val: len(val.strip()) > 0 or "Project name is required",
    ).ask()
    if project_name is None:
        sys.exit(0)
    project_name = project_name.strip()

    branch = questionary.text(
        "Branch to analyze:",
        default=DEFAULT_BRANCH,
    ).ask()
    if branch is None:
        sys.exit(0)

    scope = questionary.select(
        "Analysis scope:",
        choices=[
            "All findings (filter by severity & state)",
            "Specific findings (by hash)",
        ],
    ).ask()
    if scope is None:
        sys.exit(0)

    finding_hashes = None
    severities = DEFAULT_SEVERITIES
    states = DEFAULT_STATES

    if scope.startswith("Specific"):
        hashes_input = questionary.text(
            "Finding hashes (comma-separated):",
            validate=lambda val: (
                len(val.strip()) > 0 or "At least one hash is required"
            ),
        ).ask()
        if hashes_input is None:
            sys.exit(0)
        finding_hashes = [h.strip() for h in hashes_input.split(",") if h.strip()]
    else:
        selected_states = questionary.checkbox(
            "Checkmarx states to include:",
            choices=[
                questionary.Choice(s, checked=(s in DEFAULT_STATES))
                for s in CHECKMARX_STATES
            ],
            validate=lambda val: len(val) > 0 or "Select at least one state",
        ).ask()
        if selected_states is None:
            sys.exit(0)
        states = selected_states

        severity_choices = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        selected_severities = questionary.checkbox(
            "Severities to include:",
            choices=[
                questionary.Choice(s, checked=(s in DEFAULT_SEVERITIES))
                for s in severity_choices
            ],
            validate=lambda val: len(val) > 0 or "Select at least one severity",
        ).ask()
        if selected_severities is None:
            sys.exit(0)
        severities = selected_severities

    model_name = questionary.text(
        "AI model for triage:",
        default=DEFAULT_TRIAGE_MODEL,
    ).ask()
    if model_name is None:
        sys.exit(0)

    gitleaks_report = questionary.text(
        "Gitleaks CSV report path (or 'none' to skip):",
        validate=lambda val: (
            len(val.strip()) > 0 or "A path or 'none' is required"
        ),
    ).ask()
    if gitleaks_report is None:
        sys.exit(0)
    gitleaks_report = gitleaks_report.strip()

    if gitleaks_report.lower() != "none" and not os.path.isfile(gitleaks_report):
        click.echo(f"Error: File not found: {os.path.abspath(gitleaks_report)}")
        sys.exit(1)

    output_dir = questionary.text(
        "Output directory:",
        default=DEFAULT_OUTPUT_DIR,
    ).ask()
    if output_dir is None:
        sys.exit(0)

    return {
        "project_name": project_name,
        "branch": branch.strip(),
        "finding_hashes": finding_hashes,
        "states": states,
        "severities": severities,
        "model_name": model_name.strip(),
        "gitleaks_report": gitleaks_report.strip(),
        "output_dir": output_dir.strip(),
    }


def display_config_summary(config: dict) -> bool:
    """
    Print the configuration summary and ask for confirmation.

    Args:
        config: Dictionary from prompt_project_config()

    Returns:
        True if user confirms, False otherwise
    """
    click.echo()
    click.echo("=" * 50)
    click.echo("  Configuration Summary")
    click.echo("=" * 50)
    click.echo(f"  Project:        {config['project_name']}")
    click.echo(f"  Branch:         {config['branch']}")

    if config["finding_hashes"]:
        click.echo(f"  Findings:       {', '.join(config['finding_hashes'])}")
        click.echo("  Filters:        bypassed (specific findings)")
    else:
        click.echo(f"  States:         {', '.join(config['states'])}")
        click.echo(f"  Severities:     {', '.join(config['severities'])}")

    click.echo(f"  Model:          {config['model_name']}")
    click.echo(f"  Gitleaks:       {config['gitleaks_report']}")
    click.echo(f"  Output:         {config['output_dir']}")
    click.echo("=" * 50)
    click.echo()

    confirmed = questionary.confirm(
        "Proceed with this configuration?", default=True
    ).ask()
    return confirmed is True


def display_preprocessing_summary(
    obfuscation_report: Optional[ObfuscationReport],
    masking_report: Optional[MaskingReport],
) -> bool:
    """
    Show obfuscation and secret masking results, ask to proceed.

    Args:
        obfuscation_report: Result from obfuscate_codebase(), or None
        masking_report: Result from mask_secrets(), or None

    Returns:
        True if user confirms to proceed with triage, False otherwise
    """
    click.echo()
    click.echo("=" * 50)
    click.echo("  Preprocessing Summary")
    click.echo("=" * 50)

    if obfuscation_report:
        click.echo(
            f"  Obfuscation:    {obfuscation_report.total_replacements} "
            f"replacements in {obfuscation_report.total_files_modified} files"
        )
        if obfuscation_report.replacements_by_type:
            for pattern_type, count in obfuscation_report.replacements_by_type.items():
                click.echo(f"    - {pattern_type}: {count}")
    else:
        click.echo("  Obfuscation:    skipped (no codebase)")

    if masking_report:
        click.echo(
            f"  Secret masking: {masking_report.total_secrets_masked} secrets "
            f"masked in {masking_report.files_modified} files"
        )
        if masking_report.skipped_entries:
            click.echo(
                f"    - {len(masking_report.skipped_entries)} entries skipped"
            )
    else:
        click.echo("  Secret masking: skipped (no report provided)")

    click.echo("=" * 50)
    click.echo()

    confirmed = questionary.confirm(
        "Proceed with triage analysis?", default=True
    ).ask()
    return confirmed is True
