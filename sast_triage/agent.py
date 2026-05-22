"""
Main SAST Triage Agent using LangChain
"""

import os
import csv
import json
import datetime
import logging
from typing import Dict, List, Optional

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import ToolMessage

from sast_triage.agent_models import (
    SuggestedState,
    TriageDecision,
    derive_state,
)
from sast_triage.agent_tools import (
    read_file,
    search_in_files,
    list_directory,
    verify_analysis,
    submit_triage_decision,
    parse_csv_findings,
    get_finding_details,
)
from sast_triage.agent_logging import AgentLoggingManager
from sast_triage.checklists import (
    ChecklistError,
    render_checklist_section,
    select_checklist,
)
from sast_triage.prompts import (
    TRIAGE_SYSTEM_PROMPT,
    TRIAGE_INPUT_PROMPT_TEMPLATE,
)
from config import (
    CODEBASE_DIR,
    FINDINGS_JSON_FILE,
    FINDINGS_CSV_FILE,
    MAX_ANALYSIS_ITERATIONS,
    DEFAULT_OUTPUT_DIR,
)


class SASTTriageAgent:
    """Main SAST Triage Agent using LangChain with custom LLM endpoint"""

    logger = logging.getLogger(__name__)

    def __init__(
        self,
        project: Optional[str],
        model_name: str,
        location: Optional[str],
        temperature: float = 0.1,
        project_name: Optional[str] = None,
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        checkmarx_base_url: Optional[str] = None,
        branch: Optional[str] = None,
        repo_url: Optional[str] = None,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        compact_logs: bool = False,
    ):
        """
        Initialize the SAST Triage Agent.

        Args:
            project: GCP project ID for Vertex AI, or None for AI Studio
            location: Vertex AI region (used only when project is set)
            model_name: Gemini model name
            temperature: Model temperature for consistency
            project_name: Project name for reporting
            project_id: Project identifier for reporting
            scan_id: Scan identifier for reporting
            checkmarx_base_url: Checkmarx base URL for report links
            branch: Git branch being analyzed
            repo_url: Repository URL for logging
            output_dir: Directory for output files
            compact_logs: If True, write a reduced agent log (no input
                prompt bodies, system prompt by hash only, tool result
                bulk arrays dropped). For development analysis only.
        """
        self.project_name = project_name
        self.project_id = project_id
        self.scan_id = scan_id
        self.checkmarx_base_url = checkmarx_base_url
        self.branch = branch

        # Vertex AI when a GCP project is supplied, otherwise AI Studio
        # (GOOGLE_API_KEY). The backend is resolved by the caller; see
        # config.resolve_genai_backend.
        if project:
            self.logger.info(
                f"Initializing Gemini via Vertex AI: {model_name}"
            )
            self.llm = ChatGoogleGenerativeAI(
                model=model_name,
                temperature=temperature,
                max_retries=3,
                vertexai=True,
                project=project,
                location=location,
            )
        else:
            self.logger.info(
                f"Initializing Gemini via AI Studio: {model_name}"
            )
            self.llm = ChatGoogleGenerativeAI(
                model=model_name,
                temperature=temperature,
                max_retries=3,
            )

        self.tools = [
            read_file,
            search_in_files,
            list_directory,
            verify_analysis,
            submit_triage_decision,
        ]

        # Bind tools to the LLM
        self.llm_with_tools = self.llm.bind_tools(self.tools)

        # Store model configuration for logging
        self.model_name = model_name
        self.temperature = temperature

        # Setup agent logging with session context
        self.agent_logger = AgentLoggingManager(
            model_name=model_name,
            temperature=temperature,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            repo_url=repo_url,
            branch=branch,
            compact_logs=compact_logs,
        )

        # System and Human prompts
        self.system_prompt = TRIAGE_SYSTEM_PROMPT
        self.human_prompt_template = TRIAGE_INPUT_PROMPT_TEMPLATE

        # File to store assessment results (with timestamp)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = project_name or "unknown"
        self.assessments_file = os.path.join(
            output_dir,
            f"findings_assessment_{name}_{timestamp}.json",
        )

    def _build_system_prompt(self, finding_details: Dict) -> str:
        """Compose the base prompt with the finding's CWE-specific checklist.

        Selection is driven by the finding's `queryName` and `cweID`. If no
        checklist can be loaded the base prompt is used unchanged, so a
        checklist problem never blocks a triage run.
        """
        try:
            checklist = select_checklist(
                finding_details.get("queryName"),
                finding_details.get("cweID"),
            )
        except ChecklistError as exc:
            self.logger.warning(
                f"No checklist applied for {finding_details.get('resultHash')}: "
                f"{exc}"
            )
            return self.system_prompt

        self.logger.debug(
            f"Selected checklist '{checklist.checklist_id}' for finding"
        )
        return (
            f"{self.system_prompt}\n\n{render_checklist_section(checklist)}"
        )

    async def analyze_single_finding(
        self, result_hash: str
    ) -> TriageDecision:
        """
        Analyze a single finding and return triage decision.

        Args:
            result_hash: The finding ID to analyze

        Returns:
            TriageDecision with analysis results
        """
        finding_log = self.agent_logger.log_finding_start(result_hash)

        finding_details = get_finding_details.invoke(
            {"result_hash": result_hash}
        )
        if "error" in finding_details:
            decision = TriageDecision(
                resultHash=result_hash,
                is_vulnerable=None,
                confidence=0.0,
                suggested_state=SuggestedState.REFUSED,
                justification=(
                    f"Could not load finding details: "
                    f"{finding_details['error']}"
                ),
            )
            self.agent_logger.log_finding_complete(finding_log, decision)
            return decision

        input_prompt = self.human_prompt_template.format(
            finding_details=json.dumps(finding_details, indent=2),
            finding_id=result_hash,
        )

        system_prompt = self._build_system_prompt(finding_details)

        try:
            messages = [
                ("system", system_prompt),
                ("human", input_prompt),
            ]

            self.agent_logger.log_initial_inputs(
                finding_log, system_prompt, input_prompt
            )

            max_iterations = MAX_ANALYSIS_ITERATIONS

            for iteration in range(max_iterations):
                self.logger.debug(
                    f"  Iteration {iteration + 1}/{max_iterations}"
                )

                response = await self.llm_with_tools.ainvoke(messages)
                messages.append(response)

                # Extract token usage from LLM response
                token_usage = getattr(
                    response, "usage_metadata", None
                )
                if token_usage:
                    self.agent_logger.log_token_usage(
                        finding_log, token_usage
                    )

                # Log assistant response
                tool_calls_info = []
                if response.tool_calls:
                    tool_calls_info = [
                        {"name": tc["name"], "args": tc["args"]}
                        for tc in response.tool_calls
                    ]

                self.agent_logger.log_message(
                    finding_log,
                    "assistant",
                    response.content,
                    tool_calls_info,
                )

                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["args"]

                        self.logger.debug(f"Using tool: {tool_name}")

                        if tool_name == "submit_triage_decision":
                            try:
                                is_vulnerable = tool_args.get(
                                    "is_vulnerable"
                                )
                                confidence = tool_args.get(
                                    "confidence", 0.5
                                )
                                decision = TriageDecision(
                                    resultHash=result_hash,
                                    is_vulnerable=is_vulnerable,
                                    confidence=confidence,
                                    suggested_state=derive_state(
                                        is_vulnerable, confidence
                                    ),
                                    justification=(
                                        tool_args.get(
                                            "justification", ""
                                        )
                                    ),
                                )

                                self.agent_logger.log_finding_complete(
                                    finding_log, decision
                                )

                                self.logger.info(
                                    f"Decision submitted: "
                                    f"{decision.suggested_state.value} "
                                    f"(confidence: "
                                    f"{decision.confidence:.2f})"
                                )
                                return decision

                            except Exception as e:
                                self.logger.error(
                                    f"Error processing decision: {e}"
                                )
                                tool_result = {
                                    "error": (
                                        f"Failed to process decision: "
                                        f"{str(e)}"
                                    )
                                }
                        else:
                            tool_result = None
                            for t in self.tools:
                                if t.name == tool_name:
                                    try:
                                        tool_result = t.invoke(
                                            tool_args
                                        )
                                    except Exception as e:
                                        tool_result = {
                                            "error": str(e)
                                        }
                                    break

                            if tool_result is None:
                                tool_result = {
                                    "error": (
                                        f"Tool {tool_name} not found"
                                    )
                                }

                        self.agent_logger.log_tool_result(
                            finding_log,
                            tool_name,
                            tool_args,
                            tool_result,
                        )

                        tool_message = ToolMessage(
                            content=str(tool_result),
                            tool_call_id=tool_call["id"],
                        )
                        messages.append(tool_message)
                else:
                    prompt = (
                        "You must use a tool. Either continue "
                        "investigating with "
                        "read_file/search_in_files/list_directory, "
                        "or submit your final decision with "
                        "submit_triage_decision."
                    )
                    messages.append(("human", prompt))
                    self.agent_logger.log_message(
                        finding_log, "human", prompt
                    )

            print(
                f"  Warning: No decision submitted after "
                f"{max_iterations} iterations"
            )

            decision = TriageDecision(
                resultHash=result_hash,
                is_vulnerable=None,
                confidence=0.0,
                suggested_state=SuggestedState.REFUSED,
                justification=(
                    f"Analysis did not complete within "
                    f"{max_iterations} iterations. "
                    f"Manual review required."
                ),
            )

            self.agent_logger.log_finding_complete(
                finding_log, decision
            )
            return decision

        except Exception as e:
            self.logger.error(
                f"Error analyzing finding {result_hash}: {str(e)}"
            )
            decision = TriageDecision(
                resultHash=result_hash,
                is_vulnerable=None,
                confidence=0.0,
                suggested_state=SuggestedState.REFUSED,
                justification=(
                    f"Analysis failed due to error: {str(e)}. "
                    f"Manual review required."
                ),
            )
            self.agent_logger.log_finding_complete(
                finding_log, decision
            )
            return decision

    def update_csv_status(
        self, result_hash: str, csv_path: str = FINDINGS_CSV_FILE
    ):
        """Update the triaged status in CSV file."""
        try:
            rows = []
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                for row in reader:
                    if row["resultHash"] == result_hash:
                        row["triaged"] = "yes"
                    rows.append(row)

            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            self.logger.debug(
                f"Updated CSV: marked {result_hash} as triaged"
            )
        except Exception as e:
            self.logger.warning(
                f"Could not update CSV for {result_hash}: {str(e)}"
            )

    def save_incremental_result(self, result: Dict):
        """
        Save individual result immediately to the assessments file.

        Maintains a metadata wrapper structure around the results list.
        """
        try:
            existing_results = []
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "results" in data:
                    existing_results = data["results"]
                elif isinstance(data, list):
                    existing_results = data

            result_hash = result["resultHash"]
            updated = False
            for i, existing in enumerate(existing_results):
                if existing["resultHash"] == result_hash:
                    existing_results[i] = result
                    updated = True
                    break

            if not updated:
                existing_results.append(result)

            output = self._build_assessment_output(existing_results)

            with open(self.assessments_file, "w") as f:
                json.dump(output, f, indent=2)

            self.logger.info(
                f"Saved result to {self.assessments_file}"
            )
        except Exception as e:
            self.logger.warning(
                f"Could not save incremental result: {str(e)}"
            )

    def _build_assessment_output(
        self, triage_results: List[Dict]
    ) -> Dict:
        """
        Build the assessment output structure with metadata wrapper.

        Args:
            triage_results: List of triage result dicts

        Returns:
            Dict with metadata and results keys
        """
        total = len(triage_results)
        confirmed = sum(
            1
            for r in triage_results
            if r.get("suggested_state") == "CONFIRMED"
        )
        not_exploitable = sum(
            1
            for r in triage_results
            if r.get("suggested_state") == "NOT_EXPLOITABLE"
        )
        proposed_not_exploitable = sum(
            1
            for r in triage_results
            if r.get("suggested_state") == "PROPOSED_NOT_EXPLOITABLE"
        )
        refused = sum(
            1
            for r in triage_results
            if r.get("suggested_state") == "REFUSED"
        )

        return {
            "metadata": {
                "project_name": self.project_name,
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "branch": self.branch,
                "model": self.model_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "total_findings": total,
                "summary": {
                    "confirmed": confirmed,
                    "not_exploitable": not_exploitable,
                    "proposed_not_exploitable": proposed_not_exploitable,
                    "refused": refused,
                    "refusal_rate": (
                        round(refused / total, 4) if total else 0.0
                    ),
                },
            },
            "results": triage_results,
        }

    def get_pending_findings(self, csv_path: str) -> List[Dict]:
        """Get findings that haven't been triaged yet (triaged = 'no')."""
        try:
            findings = parse_csv_findings.invoke(
                {"file_path": csv_path}
            )
            if findings and "error" not in findings[0]:
                pending = [
                    f
                    for f in findings
                    if f.get("triaged", "").lower() == "no"
                ]
                return pending
            return []
        except Exception as e:
            self.logger.error(
                f"Error getting pending findings: {str(e)}"
            )
            return []

    async def process_all_findings(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        csv_path: str = FINDINGS_CSV_FILE,
        json_path: str = FINDINGS_JSON_FILE,
    ) -> Dict:
        """
        Process all findings from CSV and generate triage report.

        Args:
            output_dir: Directory for output files
            csv_path: Path to CSV file with findings list
            json_path: Path to JSON file with finding details

        Returns:
            Complete triage report
        """
        self.logger.info("Starting SAST triage analysis...")
        self.logger.info(f"CSV: {csv_path}")
        self.logger.info(f"JSON: {json_path}")
        self.logger.info(f"Codebase: {CODEBASE_DIR}")

        findings = self.get_pending_findings(csv_path)

        if not findings:
            self.logger.warning(
                "No pending findings to triage "
                "(all marked as 'yes' in CSV)"
            )
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, "r") as f:
                    return json.load(f)
            return []

        self.logger.info(
            f"Found {len(findings)} pending findings to triage"
        )

        triage_results = []
        for i, finding in enumerate(findings):
            self.logger.info(
                f"Analyzing finding {i + 1}/{len(findings)}: "
                f"{finding['resultHash']}"
            )

            try:
                decision = await self.analyze_single_finding(
                    finding["resultHash"]
                )

                result_dict = decision.model_dump()
                triage_results.append(result_dict)

                self.save_incremental_result(result_dict)

                self.update_csv_status(
                    finding["resultHash"], csv_path
                )

                self.logger.info(
                    f"Result: {decision.suggested_state.value}"
                )
                self.logger.info(
                    f"Confidence: "
                    f"{decision.confidence:.2f}"
                )
                self.logger.info(
                    f"Justification: "
                    f"{decision.justification[:100]}..."
                )

            except Exception as e:
                self.logger.error(
                    f"Error analyzing {finding['resultHash']}: "
                    f"{str(e)}"
                )
                error_result = {
                    "resultHash": finding["resultHash"],
                    "is_vulnerable": None,
                    "confidence": 0.0,
                    "suggested_state": "REFUSED",
                    "justification": (
                        f"Analysis failed: {str(e)}"
                    ),
                }
                triage_results.append(error_result)
                self.save_incremental_result(error_result)

                self.update_csv_status(
                    finding["resultHash"], csv_path
                )

        # Write final output with metadata
        output = self._build_assessment_output(triage_results)
        with open(self.assessments_file, "w") as f:
            json.dump(output, f, indent=2)

        # Finalize session log with summary
        self.agent_logger.finalize_session(triage_results)

        # Generate summary for display
        summary = output["metadata"]["summary"]
        summary["total_findings"] = output["metadata"]["total_findings"]
        summary["high_confidence"] = sum(
            1
            for r in triage_results
            if r["confidence"] >= 0.8
        )

        self.logger.info(
            f"Triage complete! Results saved to "
            f"{self.assessments_file}"
        )
        self.logger.info("Summary:")
        self.logger.info(f"CONFIRMED: {summary['confirmed']}")
        self.logger.info(
            f"NOT_EXPLOITABLE: {summary['not_exploitable']}"
        )
        self.logger.info(
            f"PROPOSED_NOT_EXPLOITABLE: "
            f"{summary['proposed_not_exploitable']}"
        )
        self.logger.info(f"REFUSED: {summary['refused']}")
        self.logger.info(
            f"High Confidence (>=0.8): "
            f"{summary['high_confidence']}/"
            f"{summary['total_findings']}"
        )

        # Check for code mismatch
        if summary["refused"] == summary["total_findings"]:
            error_result = [
                {"error": "Code base and findings report do not match."}
            ]
            with open(self.assessments_file, "w") as f:
                json.dump(error_result, f, indent=2)
            return error_result

        return triage_results
