#!/usr/bin/env python3
"""
SAST Triage Agent CLI - Fetches findings from Checkmarx One and runs analysis
Usage: python run_triage.py PROJECT_ID [OPTIONS]
"""

import asyncio
import csv
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sast_triage import SASTTriageAgent
from sast_triage.api import CheckmarxClient
from sast_triage.git import clone_repository
from sast_triage.config import DEFAULT_SEVERITIES


def setup_output_directory(output_dir: str) -> tuple[Path, Path, Path]:
    """
    Create output directory structure.
    
    Returns:
        Tuple of (findings_dir, codebase_dir, output_path)
    """
    output_path = Path(output_dir).resolve()
    findings_dir = output_path / "findings"
    codebase_dir = output_path / "codebase"
    
    # Create directories
    findings_dir.mkdir(parents=True, exist_ok=True)
    codebase_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Output directory: {output_path}")
    print(f"  ├── findings/")
    print(f"  └── codebase/")
    
    return findings_dir, codebase_dir, output_path


def save_findings_data(
    findings_dir: Path,
    triage_records: List[dict],
    detailed_records: List[dict]
) -> None:
    """Save findings data to CSV and JSON files."""
    csv_file = findings_dir / "triage_list.csv"
    json_file = findings_dir / "findings_details.json"
    
    # Write CSV file
    print(f"\nSaving {len(triage_records)} records to {csv_file.name}...")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["findingId", "severity", "triaged"])
        writer.writeheader()
        writer.writerows(triage_records)
    
    # Write JSON file
    print(f"Saving detailed records to {json_file.name}...")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(detailed_records, f, indent=4)
    
    print("✓ Findings data saved successfully")


async def run_triage_analysis(output_dir: Path, project_id: str = None, 
                             scan_id: str = None, checkmarx_base_url: str = None) -> int:
    """
    Run the triage analysis on the fetched data.
    
    Args:
        output_dir: Directory containing the analysis data
        project_id: Project identifier for reporting
        scan_id: Scan identifier for reporting
        checkmarx_base_url: Checkmarx base URL for report links
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Change to output directory for analysis
    original_dir = os.getcwd()
    os.chdir(output_dir)
    
    try:
        # Get LLM configuration
        llm_base_url = os.getenv("LLM_BASE_URL", "http://localhost:4000")
        llm_model = os.getenv("LLM_MODEL", "gemini-2.0-flash-exp")
        llm_api_key = os.getenv("LLM_API_KEY", "dummy-key")
        
        print(f"\nUsing LLM endpoint: {llm_base_url}")
        print(f"Using model: {llm_model}")
        print()
        
        print("Starting triage analysis...")
        print("-" * 60)
        
        # Initialize and run the agent
        agent = SASTTriageAgent(
            base_url=llm_base_url,
            model_name=llm_model,
            api_key=llm_api_key,
            temperature=0.1,
            project_id=project_id,
            scan_id=scan_id,
            checkmarx_base_url=checkmarx_base_url
        )
        
        results = await agent.process_all_findings()
        
        print("-" * 60)
        print("\n✓ Analysis complete!")
        print(f"Results saved to: findings_assessment.json")
        print(f"Updated CSV: findings/triage_list.csv")
        print(f"HTML Report: Generated with timestamp")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        os.chdir(original_dir)


@click.command()
@click.argument("project_id")
@click.option(
    "--severities",
    default=",".join(DEFAULT_SEVERITIES),
    help=f"Comma-separated list of severities (default: {','.join(DEFAULT_SEVERITIES)})"
)
@click.option(
    "--output-dir",
    default=".",
    help="Output directory for results (default: current directory)"
)
def main(
    project_id: str,
    severities: str,
    output_dir: str
) -> None:
    """
    Fetch SAST findings from Checkmarx One and run triage analysis.
    
    PROJECT_ID: The Checkmarx project ID to analyze
    """
    print("=" * 60)
    print("SAST Triage Agent - Checkmarx One Integration")
    print("=" * 60)
    print()
    
    # Check environment variables
    base_url = os.getenv("BASE_URL")
    refresh_token = os.getenv("REFRESH_TOKEN")
    
    if not all([base_url, refresh_token]):
        print("✗ Error: Missing required environment variables")
        print("Please ensure the following are set in your .env file:")
        print("  - BASE_URL: Checkmarx One instance URL")
        print("  - REFRESH_TOKEN: Your refresh token")
        sys.exit(1)
    
    # Parse severities
    severity_list = [s.strip().upper() for s in severities.split(",")]
    print(f"Project ID: {project_id}")
    print(f"Severities: {', '.join(severity_list)}")
    print(f"Output directory: {output_dir}")
    print()
    
    try:
        # Setup output directory
        findings_dir, codebase_dir, output_path = setup_output_directory(output_dir)
        
        # Initialize Checkmarx client
        print("Connecting to Checkmarx One...")
        client = CheckmarxClient(base_url, refresh_token)
        
        # Get project details and repository URL
        repo_url = client.get_project_details(project_id)
        
        # Get findings
        scan_id, findings = client.get_findings_for_project(project_id, severity_list)
        
        if not findings:
            print("\n✗ No findings found for the specified project and severities.")
            sys.exit(1)
        
        # Process findings
        triage_records, detailed_records = client.process_findings_to_records(findings)
        
        # Save findings data
        save_findings_data(findings_dir, triage_records, detailed_records)
        
        # Clone repository if URL available
        if repo_url:
            clone_success = clone_repository(repo_url, str(codebase_dir))
            if not clone_success:
                print("⚠ Warning: Repository cloning failed, continuing with analysis...")
        else:
            print("\n⚠ No repository URL found, continuing without codebase.")
        
        # Run triage analysis
        print("\n" + "=" * 60)
        print("Starting Triage Analysis")
        print("=" * 60)
        
        exit_code = asyncio.run(run_triage_analysis(output_path, project_id, scan_id, base_url))
        
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()