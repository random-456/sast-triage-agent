"""
Main SAST Triage Agent using LangChain
"""

import os
import csv
import json
import logging
from typing import Dict, List, Optional

from langchain_google_vertexai import ChatVertexAI
from langchain_google_vertexai.model_garden import ChatAnthropicVertex
from langchain_core.messages import ToolMessage

from sast_triage.agent_models import TriageDecision
from sast_triage.agent_tools import (
    read_file, search_in_files, list_directory, verify_analysis, submit_triage_decision,
    parse_csv_findings, get_finding_details
)
from sast_triage.agent_logging import AgentLoggingManager
from sast_triage.prompts import TRIAGE_SYSTEM_PROMPT, TRIAGE_INPUT_PROMPT_TEMPLATE
from config import CODEBASE_DIR, FINDINGS_JSON_FILE, FINDINGS_CSV_FILE, MAX_ANALYSIS_ITERATIONS, DEFAULT_OUTPUT_DIR

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
        output_dir: str = DEFAULT_OUTPUT_DIR
    ):
        """
        Initialize the SAST Triage Agent.

        Args:
            project: Google Cloud Project ID for Vertex AI
            location: Vertex AI location (default: europe-west4)
            model_name: Vertex AI model name
            temperature: Model temperature for consistency
            project_name: Project name for reporting
            project_id: Project identifier for reporting
            scan_id: Scan identifier for reporting
            checkmarx_base_url: Checkmarx base URL for report links
            branch: Git branch being analyzed
        """
        self.project_name = project_name
        self.project_id = project_id
        self.scan_id = scan_id
        self.checkmarx_base_url = checkmarx_base_url
        self.branch = branch

        # Initialize the appropriate LLM backend
        if "claude" in model_name.lower():
            self.logger.info(f"Initializing Claude on Vertex: {model_name}")
            self.llm = ChatAnthropicVertex(
                project=project,
                location=location,
                model_name=model_name,
                temperature=temperature,
                max_retries=3
            )
        else:
            self.logger.info(f"Initializing Gemini/Vertex: {model_name}")
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

        # System and Human prompts
        self.system_prompt = TRIAGE_SYSTEM_PROMPT
        self.human_prompt_template = TRIAGE_INPUT_PROMPT_TEMPLATE

        # File to store assessment results
        self.assessments_file = os.path.join(output_dir, f"findings_assessment_{project_name}.json")

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

                # If LLM wants to use tools
                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]

                        self.logger.debug(f"Using tool: {tool_name}")

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

                                # Log the decision
                                self.agent_logger.log_finding_complete(finding_log, decision)

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

                        # Log tool result
                        self.agent_logger.log_tool_result(finding_log, tool_name, tool_args, tool_result)

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
            decision = TriageDecision(
                resultHash=result_hash,
                assessment_result="REFUSED",
                assessment_confidence=0.0,
                assessment_justification=f"Analysis failed due to error: {str(e)}. Manual review required."
            )
            self.agent_logger.log_finding_complete(finding_log, decision)
            return decision

    def update_csv_status(self, result_hash: str, csv_path: str = FINDINGS_CSV_FILE):
        """Update the triaged status in CSV file."""
        try:
            # Read CSV
            rows = []
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                for row in reader:
                    if row['resultHash'] == result_hash:
                        row['triaged'] = 'yes'
                    rows.append(row)

            # Write updated CSV
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            self.logger.debug(f"Updated CSV: marked {result_hash} as triaged")
        except Exception as e:
            self.logger.warning(f"Could not update CSV for {result_hash}: {str(e)}")

    def save_incremental_result(self, result: Dict):
        """Save individual result immediately to output/findings_assessment.json."""
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

    def get_pending_findings(self, csv_path: str) -> List[Dict]:
        """Get findings that haven't been triaged yet (triaged = 'no')."""
        try:
            findings = parse_csv_findings.invoke({"file_path": csv_path})
            if findings and 'error' not in findings[0]:
                # Only return findings not yet triaged
                pending = [f for f in findings if f.get('triaged', '').lower() == 'no']
                return pending
            return []
        except Exception as e:
            self.logger.error(f"Error getting pending findings: {str(e)}")
            return []

    async def process_all_findings(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        csv_path: str = FINDINGS_CSV_FILE,
        json_path: str = FINDINGS_JSON_FILE
    ) -> Dict:
        """
        Process all findings from CSV and generate triage report.

        Args:
            csv_path: Path to CSV file with findings list
            json_path: Path to JSON file with finding details
            output_path: Path to save the triage results

        Returns:
            Complete triage report
        """
        self.logger.info(f"Starting SAST triage analysis...")
        self.logger.info(f"CSV: {csv_path}")
        self.logger.info(f"JSON: {json_path}")
        self.logger.info(f"Codebase: {CODEBASE_DIR}")

        # Get only pending findings (skip already triaged)
        findings = self.get_pending_findings(csv_path)

        if not findings:
            self.logger.warning("No pending findings to triage (all marked as 'yes' in CSV)")
            # Load existing results if any
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, 'r') as f:
                    return json.load(f)
            return []

        self.logger.info(f"Found {len(findings)} pending findings to triage")

        # Analyze each pending finding
        triage_results = []
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

                # Mark as triaged after analysis
                self.update_csv_status(finding['resultHash'], csv_path)

                # Print summary
                self.logger.info(f"Result: {decision.assessment_result}")
                self.logger.info(f"Confidence: {decision.assessment_confidence:.2f}")
                self.logger.info(f"Justification: {decision.assessment_justification[:100]}...")

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

                # Mark as triaged even for errors (so they don't retry indefinitely)
                self.update_csv_status(finding['resultHash'], csv_path)

        # Save results (output/findings_assessment.json)
        with open(self.assessments_file, 'w') as f:
            json.dump(triage_results, f, indent=2)

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