"""
Logging utilities for SAST Triage Agent
"""

import json
import datetime
from typing import Dict, List, Any
from pathlib import Path

from .models import TriageDecision
from .config import MAX_LOG_RESULT_LENGTH


class LoggingManager:
    """Handles comprehensive logging for agent conversations."""
    
    def __init__(self, model_name: str, temperature: float):
        """
        Initialize the logging manager.
        
        Args:
            model_name: Name of the model being used
            temperature: Temperature setting of the model
        """
        self.model_name = model_name
        self.temperature = temperature
        self.setup_logging()
    
    def setup_logging(self):
        """Setup comprehensive logging for agent conversations."""
        # Create logs directory if it doesn't exist
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Create timestamped log file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"sast_triage_{timestamp}.json"
        
        # Initialize log structure
        self.session_log = {
            "session_start": datetime.datetime.now().isoformat(),
            "model": self.model_name,
            "temperature": self.temperature,
            "findings_processed": []
        }
        
        # Write initial log
        self.save_log()
    
    def save_log(self):
        """Save the current log state to file."""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.session_log, f, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Could not save log: {e}")
    
    def log_finding_start(self, finding_id: str) -> Dict:
        """Start logging a new finding analysis."""
        finding_log = {
            "finding_id": finding_id,
            "start_time": datetime.datetime.now().isoformat(),
            "conversation": [],
            "final_decision": None,
            "end_time": None,
            "duration_seconds": None
        }
        self.session_log["findings_processed"].append(finding_log)
        return finding_log
    
    def log_message(self, finding_log: Dict, message_type: str, content: Any, tool_calls: List = None):
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
            "content": content
        }
        
        if tool_calls:
            log_entry["tool_calls"] = tool_calls
        
        finding_log["conversation"].append(log_entry)
        
        # Save incrementally
        self.save_log()
    
    def log_tool_result(self, finding_log: Dict, tool_name: str, tool_args: Dict, result: Any):
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
            "result": str(result)[:MAX_LOG_RESULT_LENGTH]  # Truncate very long results for logging
        }
        
        finding_log["conversation"].append(log_entry)
        
        # Save incrementally
        self.save_log()
    
    def log_finding_complete(self, finding_log: Dict, decision: TriageDecision):
        """
        Complete logging for a finding analysis.
        
        Args:
            finding_log: The finding log dictionary to finalize
            decision: The final triage decision for this finding
        """
        finding_log["end_time"] = datetime.datetime.now().isoformat()
        
        # Calculate duration
        start = datetime.datetime.fromisoformat(finding_log["start_time"])
        end = datetime.datetime.fromisoformat(finding_log["end_time"])
        finding_log["duration_seconds"] = (end - start).total_seconds()
        
        # Add final decision
        finding_log["final_decision"] = decision.model_dump() if decision else None
        
        # Save final state
        self.save_log()