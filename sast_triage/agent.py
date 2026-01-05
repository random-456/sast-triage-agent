"""
Main SAST Triage Agent using LangChain
"""

import os
import json
import logging
import inspect
from datetime import datetime
from typing import Dict, List, Optional

from langchain_google_vertexai import ChatVertexAI
from langchain_core.messages import ToolMessage

from sast_triage.agent_models import TriageDecision
from sast_triage.agent_tools import (
    read_file, search_in_files, list_directory, verify_analysis,
    submit_triage_decision, get_pending_findings, get_finding_details,
    set_path_manager
)
from sast_triage.agent_logging import AgentLoggingManager
from utils.report_helpers import ReportGenerator

from sast_triage.prompts import TRIAGE_SYSTEM_PROMPT, TRIAGE_INPUT_PROMPT_TEMPLATE
from config import MAX_ANALYSIS_ITERATIONS, DEFAULT_OUTPUT_DIR

class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""

    logger = logging.getLogger(__name__)

    def __init__(
        self,
        project: str,
        model_name: str,
        location: str,
        temperature: float = 0.1,
        project_name: Optional[str] = None,
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        checkmarx_base_url: Optional[str] = None,
        branch: Optional[str] = None,
        output_dir: Optional[str] = None,
        progress_callback: Optional[callable] = None,
        path_manager: "PathManager" = None
    ):
        """
        Initialize the SAST Triage Agent.

        Args:
            project: Google Cloud Project ID for Vertex AI
            location: Vertex AI location (default: europa-west4)
            model_name: Vertex AI model name
            temperature: Model temperature for consistency
            project_name: Project name for reporting
            project_id: Project identifier for reporting
            scan_id: Scan identifier for reporting
            checkmarx_base_url: Checkmarx base URL for report links
            branch: Git branch being analyzed
            output_dir: Output directory for results
            progress_callback: Optional callback for progress updates (web UI integration)
            path_manager: PathManager for session-specific paths (REQUIRED)

        Raises:
            ValueError: If path_manager is not provided
        """
        # Validate path_manager is provided
        if not path_manager:
            raise ValueError(
                "path_manager is required. "
                "Both CLI and WebUI must provide PathManager."
            )

        self.path_manager = path_manager

        # Set tool context BEFORE binding tools
        set_path_manager(self.path_manager)

        self.project_name = project_name
        self.project_id = project_id
        self.scan_id = scan_id
        self.checkmarx_base_url = checkmarx_base_url
        self.branch = branch
        self.llm = ChatVertexAI(
            project=project,
            location=location,
            model_name=model_name,
            temperature=temperature,
            max_retries=3
        )

        self.tools = [
            read_file,  # Read entire files
            search_in_files,  # Search patterns across codebase
            list_directory,  # Explore directory structure
            verify_analysis,  # Verification checkpoint before decision
            submit_triage_decision  # Submit final triage decision
        ]

        # Bind tools to the LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        # Store model configuration for logging
        self.model_name = model_name
        self.temperature = temperature

        # Setup agent logging
        self.agent_logger = AgentLoggingManager(model_name, temperature)

        # Store progress callback for web UI integration
        self.progress_callback = progress_callback

        # System and Human prompts
        self.system_prompt = TRIAGE_SYSTEM_PROMPT
        self.human_prompt_template = TRIAGE_INPUT_PROMPT_TEMPLATE

        # File to store assessment results (only if output_dir provided)
        if output_dir:
            self.output_dir = output_dir
            self.assessments_file = os.path.join(
                output_dir,
                f"findings_assessment_{project_name or 'project'}.json"
            )
        else:
            self.output_dir = None
            self.assessments_file = None

    def _extract_text_content(self, content) -> str:
        """
        Extract text from LLM response content.
        Handles both string content and multimodal content blocks.

        Args:
            content: LLM response content (string or list of content blocks)

        Returns:
            Extracted text as string
        """
        if isinstance(content, str):
            return content
        elif isinstance(content, list):
            # Handle multimodal content blocks
            text_parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text" and "text" in block:
                        text_parts.append(block["text"])
                elif isinstance(block, str):
                    text_parts.append(block)
            return " ".join(text_parts) if text_parts else ""
        else:
            return str(content) if content else ""

    def _format_tool_result_for_websocket(self, tool_name: str, tool_result, tool_args: Dict = None) -> Dict:
        """
        Format tool result for WebSocket transmission.
        Preserves structured data for frontend rendering.

        Args:
            tool_name: Name of the tool that was executed
            tool_result: Raw result from tool execution
            tool_args: Arguments passed to the tool (for context)

        Returns:
            Formatted dict with type and structured content
        """
        # Handle error results
        if isinstance(tool_result, dict) and "error" in tool_result:
            return {
                "type": "error",
                "error": tool_result["error"]
            }

        # Format based on tool type with structured data
        if tool_name == "read_file":
            if isinstance(tool_result, dict):
                return {
                    "type": "file_content",
                    "file": tool_result.get("file", tool_args.get("file_path", "unknown") if tool_args else "unknown"),
                    "total_lines": tool_result.get("total_lines", 0)
                }
            return {"type": "file_content", "file": "unknown", "total_lines": 0}

        elif tool_name == "search_in_files":
            if isinstance(tool_result, dict):
                results = tool_result.get("results", [])
                return {
                    "type": "search_results",
                    "pattern": tool_result.get("pattern", ""),
                    "file_extension": tool_result.get("file_extension", ""),
                    "matches_found": tool_result.get("matches_found", len(results)),
                    "results": results[:20]  # Limit to first 20 matches
                }
            return {"type": "search_results", "pattern": "", "matches_found": 0, "results": []}

        elif tool_name == "list_directory":
            if isinstance(tool_result, dict):
                items = tool_result.get("items", [])
                return {
                    "type": "directory_listing",
                    "directory": tool_result.get("directory", "."),
                    "total_items": tool_result.get("total_items", len(items)),
                    "items": items[:50]  # Limit to first 50 items
                }
            return {"type": "directory_listing", "directory": ".", "total_items": 0, "items": []}

        elif tool_name == "verify_analysis":
            # Include the args for display since they contain the summary
            return {
                "type": "verification",
                "status": "verified",
                "investigation_summary": tool_args.get("investigation_summary", "") if tool_args else "",
                "key_evidence": tool_args.get("key_evidence", "") if tool_args else "",
                "preliminary_assessment": tool_args.get("preliminary_assessment", "") if tool_args else "",
                "potential_gaps": tool_args.get("potential_gaps", "") if tool_args else ""
            }

        elif tool_name == "submit_triage_decision":
            if isinstance(tool_result, dict):
                return {
                    "type": "decision",
                    "status": tool_result.get("status", "submitted"),
                    "assessment_result": tool_result.get("assessment_result", ""),
                    "confidence": tool_result.get("confidence", 0)
                }
            return {"type": "decision", "status": "submitted"}

        elif tool_name == "get_finding_details":
            if isinstance(tool_result, dict):
                return {
                    "type": "finding_details",
                    "result_hash": tool_result.get("resultHash", ""),
                    "query_name": tool_result.get("queryName", ""),
                    "severity": tool_result.get("severity", "")
                }
            return {"type": "finding_details"}

        else:
            # Generic fallback - stringify but limit size
            result_str = str(tool_result)
            return {
                "type": "generic",
                "content": result_str[:2000],
                "truncated": len(result_str) > 2000
            }

    async def analyze_single_finding(self, result_hash: str) -> TriageDecision:
        """
        Analyze a single finding and return triage decision.

        Args:
            result_hash: The finding ID to analyze
            severity: Original severity from Checkmarx (unused, kept for compatibility)
            update_csv: Whether to update CSV status (unused, kept for compatibility)
        
        Returns:
            TriageDecision with analysis results
        """
        # Start logging for this finding
        finding_log = self.agent_logger.log_finding_start(result_hash)

        # Emit analysis started event for web UI
        if self.progress_callback:
            event = {
                "event": "analysis_started",
                "finding_hash": result_hash,
                "timestamp": datetime.now().isoformat()
            }
            if inspect.iscoroutinefunction(self.progress_callback):
                await self.progress_callback(event)
            else:
                self.progress_callback(event)

        # Pre-load the complete finding details including dataflow
        finding_details = get_finding_details.invoke({"result_hash": result_hash})
        if 'error' in finding_details:
            decision = TriageDecision(
                resultHash=result_hash,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Could not load finding details: {finding_details['error']}"
            )
            self.agent_logger.log_finding_complete(finding_log, decision)
            return decision

        # Create comprehensive initial context
        input_prompt = self.human_prompt_template.format(
            finding_details=json.dumps(finding_details, indent=2),
            finding_id=result_hash
        )

        try:
            # Build conversation with system prompt and user request
            messages = [
                ("system", self.system_prompt),
                ("human", input_prompt)
            ]

            # Log initial messages
            self.agent_logger.log_message(finding_log, "system", self.system_prompt)
            self.agent_logger.log_message(finding_log, "human", input_prompt)

            # Run the agent with tools - allow MORE iterations for deeper investigation
            max_iterations = MAX_ANALYSIS_ITERATIONS

            for iteration in range(max_iterations):
                self.logger.debug(f"  Iteration {iteration + 1}/{max_iterations}")

                # Get LLM response
                response = await self.llm_with_tools.ainvoke(messages)
                messages.append(response)

                # Log assistant response
                tool_calls_info = []
                if response.tool_calls:
                    tool_calls_info = [{"name": tc["name"], "args": tc["args"]} for tc in response.tool_calls]

                self.agent_logger.log_message(finding_log, "assistant", response.content, tool_calls_info)

                # Emit analysis progress event for web UI
                if self.progress_callback:
                    # Extract last action from tool calls or content
                    last_action = "Analyzing..."
                    if response.tool_calls:
                        # Use first tool name as action
                        tool_names = [tc["name"] for tc in response.tool_calls]
                        if "read_file" in tool_names:
                            last_action = "Reading code files..."
                        elif "search_in_files" in tool_names:
                            last_action = "Searching codebase..."
                        elif "list_directory" in tool_names:
                            last_action = "Exploring directory structure..."
                        elif "verify_analysis" in tool_names:
                            last_action = "Verifying analysis..."
                        elif "submit_triage_decision" in tool_names:
                            last_action = "Submitting decision..."
                    elif response.content:
                        # Use content snippet as action
                        last_action = response.content[:50] + "..." if len(response.content) > 50 else response.content

                    event = {
                        "event": "analysis_progress",
                        "finding_hash": result_hash,
                        "iteration": iteration + 1,
                        "max_iterations": max_iterations,
                        "last_action": last_action,
                        "timestamp": datetime.now().isoformat()
                    }
                    if inspect.iscoroutinefunction(self.progress_callback):
                        await self.progress_callback(event)
                    else:
                        self.progress_callback(event)

                    # Emit full agent message for real-time conversation rendering
                    tool_calls = None
                    if response.tool_calls:
                        tool_calls = [
                            {
                                "name": tc.get("name"),
                                "args": tc.get("args", {})
                            }
                            for tc in response.tool_calls
                        ]

                    agent_message_event = {
                        "event": "agent_message",
                        "finding_hash": result_hash,
                        "content": self._extract_text_content(response.content) if hasattr(response, 'content') else "",
                        "tool_calls": tool_calls,
                        "timestamp": datetime.now().isoformat()
                    }
                    if inspect.iscoroutinefunction(self.progress_callback):
                        await self.progress_callback(agent_message_event)
                    else:
                        self.progress_callback(agent_message_event)

                # If LLM wants to use tools
                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]

                        self.logger.debug(f"Using tool: {tool_name}")

                        # Emit tool execution event for web UI
                        if self.progress_callback:
                            event = {
                                "event": "tool_execution",
                                "finding_hash": result_hash,
                                "tool_name": tool_name,
                                "tool_args": tool_args,
                                "timestamp": datetime.now().isoformat()
                            }
                            if inspect.iscoroutinefunction(self.progress_callback):
                                await self.progress_callback(event)
                            else:
                                self.progress_callback(event)

                        # Check if this is the submit_triage_decision tool
                        if tool_name == "submit_triage_decision":
                            # Extract decision from tool arguments
                            try:
                                decision = TriageDecision(
                                    resultHash=result_hash,
                                    assessment_result="CONFIRMED" if tool_args.get("is_exploitable") else "NOT_EXPLOITABLE",
                                    assessment_confidence=tool_args.get("confidence", 0.5),
                                    assessment_justification=tool_args.get("justification", "")
                                )

                                # Format result for WebSocket
                                formatted_content = {
                                    "type": "decision",
                                    "status": "submitted",
                                    "assessment_result": decision.assessment_result,
                                    "confidence": decision.assessment_confidence,
                                    "justification": decision.assessment_justification
                                }

                                # Emit tool_result event for web UI so the bubble appears
                                if self.progress_callback:
                                    tool_result_event = {
                                        "event": "tool_result",
                                        "finding_hash": result_hash,
                                        "tool": tool_name,
                                        "args": tool_args,
                                        "content": formatted_content,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                    if inspect.iscoroutinefunction(self.progress_callback):
                                        await self.progress_callback(tool_result_event)
                                    else:
                                        self.progress_callback(tool_result_event)

                                # Log tool result so it appears in saved conversation_log
                                self.agent_logger.log_tool_result(
                                    finding_log, tool_name, tool_args, None,
                                    formatted_content=formatted_content
                                )

                                # Log the decision
                                self.agent_logger.log_finding_complete(finding_log, decision)

                                # Calculate duration
                                duration_seconds = 0
                                if "start_time" in finding_log:
                                    try:
                                        start_time = datetime.fromisoformat(finding_log["start_time"])
                                        duration_seconds = (datetime.now() - start_time).total_seconds()
                                    except Exception:
                                        pass

                                # Emit analysis complete event for web UI
                                if self.progress_callback:
                                    event = {
                                        "event": "analysis_complete",
                                        "finding_hash": result_hash,
                                        "result": decision.assessment_result,
                                        "confidence": decision.assessment_confidence,
                                        "justification": decision.assessment_justification,
                                        "duration_seconds": duration_seconds,
                                        "timestamp": datetime.now().isoformat()
                                    }
                                    if inspect.iscoroutinefunction(self.progress_callback):
                                        await self.progress_callback(event)
                                    else:
                                        self.progress_callback(event)

                                self.logger.info(f"Decision submitted: {decision.assessment_result} (confidence: {decision.assessment_confidence:.2f})")
                                return decision

                            except Exception as e:
                                self.logger.error(f"Error processing decision: {e}")
                                tool_result = {"error": f"Failed to process decision: {str(e)}"}
                        else:
                            # Execute other tools normally
                            tool_result = None
                            for t in self.tools:
                                if t.name == tool_name:
                                    try:
                                        tool_result = t.invoke(tool_args)
                                    except Exception as e:
                                        tool_result = {"error": str(e)}
                                    break

                            if tool_result is None:
                                tool_result = {"error": f"Tool {tool_name} not found"}

                        # Format result ONCE for both logging and WebSocket
                        formatted_content = self._format_tool_result_for_websocket(tool_name, tool_result, tool_args)

                        # Log tool result with formatted content
                        self.agent_logger.log_tool_result(
                            finding_log, tool_name, tool_args, tool_result,
                            formatted_content=formatted_content
                        )

                        # Emit tool result event for web UI real-time updates
                        if self.progress_callback:
                            tool_result_event = {
                                "event": "tool_result",
                                "finding_hash": result_hash,
                                "tool": tool_name,
                                "args": tool_args,
                                "content": formatted_content,
                                "timestamp": datetime.now().isoformat()
                            }
                            if inspect.iscoroutinefunction(self.progress_callback):
                                await self.progress_callback(tool_result_event)
                            else:
                                self.progress_callback(tool_result_event)

                        # Add tool result to conversation
                        tool_message = ToolMessage(
                            content=str(tool_result),
                            tool_call_id=tool_call["id"]
                        )
                        messages.append(tool_message)

                else:
                    # No tool calls - force tool usage immediately
                    prompt = "You must use a tool. Either continue investigating with read_file/search_in_files/list_directory, or submit your final decision with submit_triage_decision."
                    messages.append(("human", prompt))
                    self.agent_logger.log_message(finding_log, "human", prompt)

            # If we reach here, no decision was submitted via tool
            print(f"  Warning: No decision submitted after {max_iterations} iterations")

            # Return a timeout/refused decision
            decision = TriageDecision(
                resultHash=result_hash,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis did not complete within {max_iterations} iterations. Manual review required."
            )

            self.agent_logger.log_finding_complete(finding_log, decision)
            return decision

        except Exception as e:
            self.logger.error(f"Error analyzing finding {result_hash}: {str(e)}")

            # Emit analysis failed event for web UI
            if self.progress_callback:
                event = {
                    "event": "analysis_failed",
                    "finding_hash": result_hash,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                if inspect.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(event)
                else:
                    self.progress_callback(event)

            decision = TriageDecision(
                resultHash=result_hash,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis failed due to error: {str(e)}. Manual review required."
            )
            self.agent_logger.log_finding_complete(finding_log, decision)
            return decision

    def mark_finding_analyzed(self, result_hash: str):
        """
        Mark a finding as analyzed in the JSON file.

        Updates agent_analyzed field to True for the specified finding.
        """
        try:
            json_path = self.path_manager.findings_json_file

            # Read current findings
            with open(json_path, 'r', encoding='utf-8') as f:
                findings = json.load(f)

            # Update the specific finding
            updated = False
            for finding in findings:
                if finding.get('resultHash') == result_hash:
                    finding['agent_analyzed'] = True
                    updated = True
                    break

            if not updated:
                self.logger.warning(f"Finding {result_hash} not found in JSON file")
                return

            # Write back
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=4)

            self.logger.debug(f"Marked finding {result_hash} as analyzed")

        except Exception as e:
            self.logger.error(f"Error updating finding status: {e}")

    def save_incremental_result(self, result: Dict):
        """
        Save incremental result to output file (legacy - for backward compatibility).

        NOTE: New code should update session.json directly instead.
        This method only works if output_dir was provided during initialization.
        """
        if not self.assessments_file:
            # No output_dir specified - skip saving to file
            return

        try:
            # Load existing results if file exists
            existing_results = []
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, 'r') as f:
                    existing_results = json.load(f)

            # Add new result (or update if finding already exists)
            result_hash = result['resultHash']
            updated = False
            for i, existing in enumerate(existing_results):
                if existing['resultHash'] == result_hash:
                    existing_results[i] = result
                    updated = True
                    break

            if not updated:
                existing_results.append(result)

            # Save back to file
            with open(self.assessments_file, 'w') as f:
                json.dump(existing_results, f, indent=2)

            self.logger.info(f"Saved result to {self.assessments_file}")
        except Exception as e:
            self.logger.warning(f"Could not save incremental result: {str(e)}")

    def get_pending_findings(self) -> List[Dict]:
        """Get findings that haven't been analyzed yet."""
        try:
            json_path = self.path_manager.findings_json_file

            with open(json_path, 'r', encoding='utf-8') as f:
                findings = json.load(f)

            # Filter for unanalyzed findings
            pending = [f for f in findings if not f.get('agent_analyzed', False)]

            self.logger.info(f"Found {len(pending)} pending findings")
            return pending

        except Exception as e:
            self.logger.error(f"Error reading findings: {e}")
            return []

    async def process_all_findings(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR
    ) -> Dict:
        """
        Process all findings from JSON and generate triage report.

        Args:
            output_dir: Path to save the triage results

        Returns:
            Complete triage report
        """

        self.logger.info(f"Starting SAST triage analysis...")
        self.logger.info(f"Findings JSON: {self.path_manager.findings_json_file}")
        self.logger.info(f"Codebase: {self.path_manager.codebase_dir}")

        # Get only pending findings (skip already analyzed)
        findings = self.get_pending_findings()

        if not findings:
            self.logger.warning("No pending findings to triage (all marked as analyzed)")
            # Load existing results if any
            if self.assessments_file and os.path.exists(self.assessments_file):
                with open(self.assessments_file, 'r') as f:
                    return json.load(f)
            return []

        self.logger.info(f"Found {len(findings)} pending findings to triage")

        # Initialize report generator
        report_gen = ReportGenerator(
            output_dir=output_dir,
            project_name=self.project_name or "Unknown",
            project_id=self.project_id or "Unknown",
            scan_id=self.scan_id,
            base_url=self.checkmarx_base_url,
            branch=self.branch,
            model_name=self.model_name
        )

        # Load all finding details for report
        with open(self.path_manager.findings_json_file, 'r') as f:
            all_details = {d['resultHash']: d for d in json.load(f)}

        # Get total count including already triaged
        total_count = len(all_details)

        # Initialize report with total count
        report_gen.initialize_report(total_findings=total_count)

        # Add already triaged findings to report if they exist
        if self.assessments_file and os.path.exists(self.assessments_file):
            with open(self.assessments_file, 'r') as f:
                existing_results = json.load(f)
                for idx, result in enumerate(existing_results):
                    result_hash = result.get('resultHash')
                    if result_hash in all_details:
                        report_gen.add_finding(
                            finding_details=all_details[result_hash],
                            assessment=result,
                            current=idx + 1,
                            total=total_count
                        )

        # Analyze each pending finding
        triage_results = []
        existing_count = total_count - len(findings)
        for i, finding in enumerate(findings):
            self.logger.info(f"Analyzing finding {i+1}/{len(findings)}: {finding['resultHash']}")

            try:
                decision = await self.analyze_single_finding(
                    finding['resultHash']
                )

                result_dict = decision.model_dump()
                triage_results.append(result_dict)

                # Save result
                self.save_incremental_result(result_dict)

                # Mark as analyzed after analysis
                self.mark_finding_analyzed(finding['resultHash'])

                # Print summary
                self.logger.info(f"Result: {decision.assessment_result}")
                self.logger.info(f"Confidence: {decision.assessment_confidence:.2f}")
                self.logger.info(f"Justification: {decision.assessment_justification[:100]}...")

                # Emit batch progress event for web UI
                if self.progress_callback:
                    event = {
                        "event": "batch_progress",
                        "completed": i + 1,
                        "total": len(findings),
                        "current_finding_hash": finding['resultHash'],
                        "timestamp": datetime.now().isoformat()
                    }
                    if inspect.iscoroutinefunction(self.progress_callback):
                        await self.progress_callback(event)
                    else:
                        self.progress_callback(event)

                # Add to HTML report
                finding_details = all_details.get(finding['resultHash'], {})
                report_gen.add_finding(
                    finding_details=finding_details,
                    assessment=result_dict,
                    current=existing_count + i + 1,
                    total=total_count
                )

            except Exception as e:
                self.logger.error(f"Error analyzing {finding['resultHash']}: {str(e)}")
                # Save error result
                error_result = {
                    'resultHash': finding['resultHash'],
                    'assessment_result': 'REFUSED',
                    'assessment_confidence': 0.0,
                    'assessment_justification': f'Analysis failed: {str(e)}'
                }
                triage_results.append(error_result)
                self.save_incremental_result(error_result)

                # Mark as analyzed even for errors (so they don't retry indefinitely)
                self.mark_finding_analyzed(finding['resultHash'])

                # Add error to HTML report
                finding_details = all_details.get(finding['resultHash'], {})
                report_gen.add_finding(
                    finding_details=finding_details,
                    assessment=error_result,
                    current=existing_count + i + 1,
                    total=total_count
                )

        # Save results to output file (only if output_dir specified)
        if self.assessments_file:
            self.logger.info(f"Saving {len(triage_results)} results to {self.assessments_file}")
            with open(self.assessments_file, 'w') as f:
                json.dump(triage_results, f, indent=2)
            self.logger.info(f"Results saved to {self.assessments_file}")

        self.logger.info(f"HTML report generated: {report_gen.report_path}")

        # Generate summary for display
        summary = {
            'total_findings': len(triage_results),
            'confirmed': sum(1 for r in triage_results if r['assessment_result'] == 'CONFIRMED'),
            'not_exploitable': sum(1 for r in triage_results if r['assessment_result'] == 'NOT_EXPLOITABLE'),
            'refused': sum(1 for r in triage_results if r['assessment_result'] == 'REFUSED'),
            'high_confidence': sum(1 for r in triage_results if r['assessment_confidence'] >= 0.8)
        }

        self.logger.info(f"Triage complete! Results saved to {self.assessments_file}")
        self.logger.info("Summary:")
        self.logger.info(f"CONFIRMED: {summary['confirmed']}")
        self.logger.info(f"NOT_EXPLOITABLE: {summary['not_exploitable']}")
        self.logger.info(f"REFUSED: {summary['refused']}")
        self.logger.info(f"High Confidence (>=0.8): {summary['high_confidence']}/{summary['total_findings']}")

        # Check for code mismatch
        if summary['refused'] == summary['total_findings']:
            error_result = [{"error": "Code base and findings report do not match."}]
            with open(self.assessments_file, 'w') as f:
                json.dump(error_result, f, indent=2)
            return error_result

        return triage_results