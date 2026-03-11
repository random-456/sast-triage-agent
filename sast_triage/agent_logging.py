"""
Logging utilities for SAST Triage Agent
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from sast_triage.agent_models import TriageDecision
from config import MAX_LOG_RESULT_LENGTH


class AgentLoggingManager:
    """Handles comprehensive logging for agent conversations."""

    def __init__(
        self,
        model_name: str,
        temperature: float,
        project_name: Optional[str] = None,
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        repo_url: Optional[str] = None,
        branch: Optional[str] = None,
    ):
        """
        Initialize the logging manager.

        Args:
            model_name: Name of the model being used
            temperature: Temperature setting of the model
            project_name: Project name for session context
            project_id: Project identifier for session context
            scan_id: Scan identifier for session context
            repo_url: Repository URL for session context
            branch: Git branch being analyzed
        """
        self.model_name = model_name
        self.temperature = temperature
        self.project_name = project_name
        self.project_id = project_id
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.branch = branch
        self.setup_logging()

    def setup_logging(self):
        """Setup comprehensive logging for agent conversations."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"sast_triage_{timestamp}.json"

        self.session_log = {
            "session_start": datetime.datetime.now().isoformat(),
            "session_metadata": {
                "model": self.model_name,
                "temperature": self.temperature,
                "project_name": self.project_name,
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "repo_url": self.repo_url,
                "branch": self.branch,
            },
            "preprocessing": {},
            "findings_processed": [],
            "session_summary": {},
        }

        self.save_log()

    def save_log(self):
        """Save the current log state to file."""
        try:
            with open(self.log_file, "w") as f:
                json.dump(self.session_log, f, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Could not save log: {e}")

    def log_finding_start(self, result_hash: str) -> Dict:
        """Start logging a new finding analysis."""
        finding_log = {
            "result_hash": result_hash,
            "start_time": datetime.datetime.now().isoformat(),
            "conversation": [],
            "token_usage": {"input": 0, "output": 0, "total": 0},
            "final_decision": None,
            "end_time": None,
            "duration_seconds": None,
        }
        self.session_log["findings_processed"].append(finding_log)
        return finding_log

    def log_message(
        self,
        finding_log: Dict,
        message_type: str,
        content: Any,
        tool_calls: List = None,
    ):
        """
        Log a message in the conversation.

        Args:
            finding_log: The finding log dictionary to append to
            message_type: Type of message (e.g., 'system', 'human', 'assistant')
            content: The message content
            tool_calls: Optional list of tool calls made in this message
        """
        log_entry = {
            "type": message_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "content": content,
        }

        if tool_calls:
            log_entry["tool_calls"] = tool_calls

        finding_log["conversation"].append(log_entry)

        self.save_log()

    def log_tool_result(
        self,
        finding_log: Dict,
        tool_name: str,
        tool_args: Dict,
        result: Any,
    ):
        """
        Log a tool execution result.

        Args:
            finding_log: The finding log dictionary to append to
            tool_name: Name of the tool that was executed
            tool_args: Arguments passed to the tool
            result: The result returned by the tool (will be truncated if too long)
        """
        log_entry = {
            "type": "tool_result",
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": tool_name,
            "args": tool_args,
            "result": str(result)[:MAX_LOG_RESULT_LENGTH],
        }

        finding_log["conversation"].append(log_entry)

        self.save_log()

    def log_token_usage(self, finding_log: Dict, token_usage: Dict):
        """
        Accumulate token usage for a finding analysis.

        Args:
            finding_log: The finding log dictionary to update
            token_usage: Dict with input_tokens, output_tokens, total_tokens
        """
        finding_log["token_usage"]["input"] += token_usage.get(
            "input_tokens", 0
        )
        finding_log["token_usage"]["output"] += token_usage.get(
            "output_tokens", 0
        )
        finding_log["token_usage"]["total"] += token_usage.get(
            "total_tokens", 0
        )
        self.save_log()

    def log_finding_complete(self, finding_log: Dict, decision: TriageDecision):
        """
        Complete logging for a finding analysis.

        Args:
            finding_log: The finding log dictionary to finalize
            decision: The final triage decision for this finding
        """
        finding_log["end_time"] = datetime.datetime.now().isoformat()

        start = datetime.datetime.fromisoformat(finding_log["start_time"])
        end = datetime.datetime.fromisoformat(finding_log["end_time"])
        finding_log["duration_seconds"] = (end - start).total_seconds()

        finding_log["final_decision"] = (
            decision.model_dump() if decision else None
        )

        self.save_log()

    def log_preprocessing(
        self,
        obfuscation_report=None,
        masking_report=None,
    ):
        """
        Record preprocessing reports in the session log.

        Args:
            obfuscation_report: ObfuscationReport from codebase obfuscation
            masking_report: MaskingReport from secret masking
        """
        if obfuscation_report:
            self.session_log["preprocessing"]["obfuscation"] = {
                "files_processed": obfuscation_report.total_files_processed,
                "files_modified": obfuscation_report.total_files_modified,
                "total_replacements": obfuscation_report.total_replacements,
                "replacements_by_type": (
                    obfuscation_report.replacements_by_type
                ),
            }
        if masking_report:
            self.session_log["preprocessing"]["secret_masking"] = {
                "csv_path": masking_report.csv_path,
                "total_entries": masking_report.total_entries_in_csv,
                "secrets_masked": masking_report.total_secrets_masked,
                "files_modified": masking_report.files_modified,
                "skipped": len(masking_report.skipped_entries),
            }
        self.save_log()

    def finalize_session(self, triage_results: List[Dict]):
        """
        Write session summary with totals after all findings are processed.

        Args:
            triage_results: List of triage result dicts from the analysis run
        """
        findings_processed = self.session_log["findings_processed"]

        confirmed = sum(
            1
            for r in triage_results
            if r.get("assessment_result") == "CONFIRMED"
        )
        not_exploitable = sum(
            1
            for r in triage_results
            if r.get("assessment_result") == "NOT_EXPLOITABLE"
        )
        refused = sum(
            1
            for r in triage_results
            if r.get("assessment_result") == "REFUSED"
        )

        self.session_log["session_summary"] = {
            "total_findings": len(triage_results),
            "total_tokens": {
                "input": sum(
                    f.get("token_usage", {}).get("input", 0)
                    for f in findings_processed
                ),
                "output": sum(
                    f.get("token_usage", {}).get("output", 0)
                    for f in findings_processed
                ),
                "total": sum(
                    f.get("token_usage", {}).get("total", 0)
                    for f in findings_processed
                ),
            },
            "confirmed": confirmed,
            "not_exploitable": not_exploitable,
            "refused": refused,
            "session_end": datetime.datetime.now().isoformat(),
        }
        self.save_log()
