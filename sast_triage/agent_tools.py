"""
Tool definitions for SAST Triage Agent
"""

import os
import json
import re
import glob
from typing import Dict, List, Optional

from langchain_core.tools import tool

from config import MAX_SEARCH_RESULTS

# Module-level variable for current execution context
_current_path_manager: Optional["PathManager"] = None


def set_path_manager(path_manager: "PathManager"):
    """
    Set the path manager for tool execution context.
    Called by SASTTriageAgent before running tools.
    """
    global _current_path_manager
    _current_path_manager = path_manager


def get_current_codebase_dir() -> str:
    """Get current codebase directory based on context."""
    if _current_path_manager:
        return _current_path_manager.codebase_dir
    raise RuntimeError(
        "PathManager not set. Agent tools require session context. "
        "Both CLI and WebUI must provide PathManager to agent."
    )


def get_current_findings_json() -> str:
    """Get current findings JSON path based on context."""
    if _current_path_manager:
        return _current_path_manager.findings_json_file
    raise RuntimeError(
        "PathManager not set. Agent tools require session context. "
        "Both CLI and WebUI must provide PathManager to agent."
    )


def validate_safe_path(base_path: str, requested_path: str) -> str:
    """
    Validate that requested path stays within base_path boundary.
    Prevents directory traversal attacks.

    Args:
        base_path: The base directory that should not be escaped
        requested_path: The requested path to validate

    Returns:
        The validated absolute path

    Raises:
        ValueError: If path traversal is detected
    """
    # Get absolute paths
    base = os.path.abspath(base_path)
    # Remove leading slash and join with base
    clean_path = requested_path.lstrip('/').lstrip('\\')
    full_path = os.path.abspath(os.path.join(base, clean_path))

    # Check if the resolved path is within the base path
    # Using os.path.commonpath to ensure the path doesn't escape
    try:
        if not os.path.commonpath([base, full_path]) == base:
            raise ValueError(f"Path traversal attempt detected: {requested_path}")
    except ValueError:
        # commonpath raises ValueError if paths are on different drives on Windows
        raise ValueError(f"Path traversal attempt detected: {requested_path}")

    return full_path


@tool
def get_pending_findings() -> Dict:
    """
    Get all findings that haven't been analyzed yet.

    Returns findings where agent_analyzed=False from the JSON file.
    """
    try:
        json_path = get_current_findings_json()

        with open(json_path, 'r', encoding='utf-8') as f:
            all_findings = json.load(f)

        # Filter for unanalyzed findings
        pending = [
            f for f in all_findings
            if not f.get('agent_analyzed', False)
        ]

        return {
            "success": True,
            "total_findings": len(all_findings),
            "pending_count": len(pending),
            "findings": pending,
            "message": f"Found {len(pending)} pending findings out of {len(all_findings)} total"
        }

    except FileNotFoundError:
        return {"success": False, "error": "Findings file not found"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def get_finding_details(result_hash: str) -> Dict:
    """
    Get detailed information for a specific finding from JSON file.

    Args:
        result_hash: The result hash to look up

    Returns:
        Detailed finding information including dataflow
    """
    try:
        json_path = get_current_findings_json()

        with open(json_path, 'r', encoding='utf-8') as f:
            all_findings = json.load(f)

        for finding in all_findings:
            if finding['resultHash'] == result_hash:
                return finding

        return {"error": f"Finding {result_hash} not found in details"}
    except Exception as e:
        return {"error": f"Failed to get finding details: {str(e)}"}


@tool
def read_file(file_path: str) -> Dict:
    """
    Read an entire file from the codebase.

    Args:
        file_path: Path to the file relative to codebase

    Returns:
        Complete file contents with line numbers
    """
    try:
        codebase_dir = get_current_codebase_dir()

        # Validate path to prevent directory traversal
        try:
            full_path = validate_safe_path(codebase_dir, file_path)
        except ValueError as e:
            return {"error": f"Invalid path: {str(e)}"}

        if not os.path.exists(full_path):
            return {"error": f"File not found: {file_path}"}

        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # No limit - Gemini etc. have a huge context
        result = {
            'file': file_path,
            'total_lines': len(lines),
            'content': []
        }

        for i, line in enumerate(lines):
            result['content'].append(f"{i+1:5}: {line.rstrip()}")

        return result
    except Exception as e:
        return {"error": f"Failed to read file: {str(e)}"}


@tool
def search_in_files(pattern: str, file_extension: str) -> Dict:
    """
    Search for a pattern in files within the codebase.

    Args:
        pattern: String or regex to search for
        file_extension: File extension to search (e.g. "py", "js", "ts")

    Returns:
        Search results with file paths and matching lines
    """
    try:
        codebase_dir = get_current_codebase_dir()
        results = []
        file_pattern = f"*.{file_extension}"
        search_path = os.path.join(codebase_dir, "**", file_pattern)
        files = glob.glob(search_path, recursive=True)

        pattern_re = re.compile(pattern, re.IGNORECASE)
        max_results = MAX_SEARCH_RESULTS  # Safety cap

        for file_path in files:  # Search ALL files, no limit
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if pattern_re.search(line):
                            rel_path = os.path.relpath(file_path, codebase_dir)
                            results.append({
                                'file': rel_path,
                                'line': i + 1,
                                'content': line.strip()
                            })
                            if len(results) >= max_results:
                                break
                if len(results) >= max_results:
                    break
            except:
                continue

        return {
            'pattern': pattern,
            'file_extension': file_extension,
            'matches_found': len(results),
            'results': results
        }
    except Exception as e:
        return {"error": f"Search failed: {str(e)}"}


@tool
def submit_triage_decision(
    is_exploitable: bool,
    confidence: float,
    justification: str
) -> Dict:
    """
    Submit the final triage decision after completing analysis.

    Args:
        is_exploitable: True if the vulnerability is exploitable, False if not
        confidence: Confidence level between 0.0 and 1.0
        justification: Detailed explanation of the decision

    Returns:
        Confirmation of decision submission
    """
    # Validate confidence is in range
    if not 0.0 <= confidence <= 1.0:
        return {"error": f"Confidence must be between 0.0 and 1.0, got {confidence}"}

    # Convert boolean to assessment result
    assessment_result = "CONFIRMED" if is_exploitable else "NOT_EXPLOITABLE"

    return {
        "status": "decision_submitted",
        "assessment_result": assessment_result,
        "confidence": confidence,
        "justification": justification
    }


@tool
def list_directory(directory_path: str) -> Dict:
    """
    List files and directories in a given path within the codebase.

    Args:
        directory_path: Path relative to codebase (use "." for root)

    Returns:
        List of files and directories
    """
    try:
        codebase_dir = get_current_codebase_dir()

        # Validate path to prevent directory traversal
        if directory_path == ".":
            full_path = codebase_dir
        else:
            try:
                full_path = validate_safe_path(codebase_dir, directory_path)
            except ValueError as e:
                return {"error": f"Invalid path: {str(e)}"}

        if not os.path.exists(full_path):
            return {"error": f"Directory not found: {directory_path}"}

        items = []
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            items.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else None
            })

        return {
            'directory': directory_path,
            'total_items': len(items),
            'items': sorted(items, key=lambda x: (x['type'], x['name']))
        }
    except Exception as e:
        return {"error": f"Failed to list directory: {str(e)}"}


@tool
def verify_analysis(
    investigation_summary: str,
    key_evidence: str,
    preliminary_assessment: str,
    potential_gaps: str
) -> Dict:
    """
    Verification checkpoint before final decision. Step back and review your analysis.

    Articulate your investigation to ensure you haven't overlooked anything.
    This is routine quality assurance, not because something is wrong with your analysis.

    Args:
        investigation_summary: Brief summary of what you investigated
        key_evidence: The main evidence supporting your assessment
        preliminary_assessment: Your current assessment (CONFIRMED or NOT_EXPLOITABLE)
        potential_gaps: Areas you're uncertain about (or "none" if complete)

    Returns:
        Verification acknowledgment - proceed to submit when satisfied
    """
    return {
        "status": "verification_complete",
        "next_step": (
            "If you identified gaps, continue investigation. "
            "Otherwise, proceed to submit_triage_decision with your final assessment."
        )
    }