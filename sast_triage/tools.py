"""
Tool definitions for SAST Triage Agent
"""

import os
import csv
import json
import re
import glob
from typing import Dict, List

from langchain_core.tools import tool

from .config import CODEBASE_PATH, DEFAULT_CSV_FILE, DEFAULT_JSON_FILE, MAX_SEARCH_RESULTS


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
def parse_csv_findings(file_path: str = DEFAULT_CSV_FILE) -> List[Dict]:
    """
    Parse the CSV file containing SAST findings list.
    
    Args:
        file_path: Path to the CSV file with findingId, severity, triaged columns
    
    Returns:
        List of finding records from CSV
    """
    try:
        findings = []
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['triaged'].lower() == 'no':
                    findings.append({
                        'findingId': row['findingId'],
                        'severity': row['severity'],
                        'triaged': row['triaged']
                    })
        return findings
    except Exception as e:
        return [{"error": f"Failed to parse CSV: {str(e)}"}]


@tool
def get_finding_details(finding_id: str, json_path: str = DEFAULT_JSON_FILE) -> Dict:
    """
    Get detailed information for a specific finding from JSON file.
    
    Args:
        finding_id: The finding ID to look up
        json_path: Path to the JSON file with detailed findings
    
    Returns:
        Detailed finding information including dataflow
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            all_findings = json.load(f)
        
        for finding in all_findings:
            if finding['findingId'] == finding_id:
                return finding
        
        return {"error": f"Finding {finding_id} not found in details"}
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
        # Validate path to prevent directory traversal
        try:
            full_path = validate_safe_path(CODEBASE_PATH, file_path)
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
        results = []
        file_pattern = f"*.{file_extension}"
        search_path = os.path.join(CODEBASE_PATH, "**", file_pattern)
        files = glob.glob(search_path, recursive=True)
        
        pattern_re = re.compile(pattern, re.IGNORECASE)
        max_results = MAX_SEARCH_RESULTS  # Safety cap
        
        for file_path in files:  # Search ALL files, no limit
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if pattern_re.search(line):
                            rel_path = os.path.relpath(file_path, CODEBASE_PATH)
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
        # Validate path to prevent directory traversal
        if directory_path == ".":
            full_path = CODEBASE_PATH
        else:
            try:
                full_path = validate_safe_path(CODEBASE_PATH, directory_path)
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