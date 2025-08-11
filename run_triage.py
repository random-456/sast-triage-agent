#!/usr/bin/env python3
"""
Simple runner script for the SAST Triage Agent
Usage: python run_triage.py
"""

import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sast_triage_agent import SASTTriageAgent


def check_prerequisites():
    """Check if required files and directories exist."""
    checks = {
        'CSV file': 'findings/triage_list.csv',
        'JSON file': 'findings/findings_details.json',
        'Codebase directory': 'codebase'
    }
    
    all_good = True
    for name, path in checks.items():
        if os.path.exists(path):
            print(f"✓ {name}: {path}")
        else:
            print(f"✗ {name}: {path} NOT FOUND")
            all_good = False
    
    return all_good


async def main():
    """Main entry point."""
    print("=" * 60)
    print("SAST Triage Agent - Checkmarx Finding Analyzer")
    print("=" * 60)
    print()
    
    # Check prerequisites
    print("Checking prerequisites...")
    if not check_prerequisites():
        print("\nError: Missing required files or directories.")
        print("Please ensure:")
        print("  1. findings/triage_list.csv exists")
        print("  2. findings/findings_details.json exists")
        print("  3. /codebase directory contains the source code")
        return 1
    
    print("\nPrerequisites OK!")
    print()
    
    # Get configuration from environment or use defaults
    base_url = os.getenv('LLM_BASE_URL', 'http://localhost:4000')
    model_name = os.getenv('LLM_MODEL', 'gemini-2.0-flash-exp')
    api_key = os.getenv('LLM_API_KEY', 'dummy-key')
    
    print(f"Using LLM endpoint: {base_url}")
    print(f"Using model: {model_name}")
    print()
    
    print("Starting analysis...")
    print("-" * 60)
    
    try:
        # Initialize and run the agent
        agent = SASTTriageAgent(
            base_url=base_url,
            model_name=model_name,
            api_key=api_key,
            temperature=0.1
        )
        
        results = await agent.process_all_findings()
        
        print("-" * 60)
        print("\n✓ Analysis complete!")
        print(f"Results saved to: findings_assessment.json")
        print(f"Updated CSV: findings/triage_list.csv")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)