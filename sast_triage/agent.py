"""
Main SAST Triage Agent using LangChain
"""

import os
import csv
import json
import datetime
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_google_vertexai import ChatVertexAI

from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueResult,
    SuggestedState,
    TriageDecision,
)
from sast_triage.agent_tools import (
    read_file,
    search_in_files,
    list_directory,
    parse_csv_findings,
    get_finding_details,
)
from sast_triage.checklists import select_checklist_with_method
from sast_triage.graph import (
    TriageState,
    aggregate_node,
    build_per_finding_graph,
    make_analyst_node,
    make_critic_node,
    make_research_node,
)
from sast_triage.session_log import LogMode, SessionLogger
from utils.path_helpers import io_safe
from config import (
    ANALYST_TEMPERATURES,
    CODEBASE_DIR,
    CONFIDENCE_AGREEMENT_WEIGHT,
    CONFIDENCE_THRESHOLD,
    CRITIC_TEMPERATURE,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SAMPLES,
    FINDINGS_CSV_FILE,
    FINDINGS_JSON_FILE,
    GRAPH_RECURSION_LIMIT,
    INITIAL_SAMPLES,
    MAX_REANALYSIS_LOOPS,
    MAX_RESEARCH_ITERATIONS,
    MAX_RESEARCH_STALL,
    MAX_TOOL_CALLS_PER_RESEARCH,
    NON_CONVERGENT_CONFIDENCE_CAP,
)


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
        repo_url: Optional[str] = None,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        log_mode: LogMode = LogMode.RICH,
    ):
        """
        Initialize the SAST Triage Agent.

        Args:
            project: GCP project ID for Vertex AI.
            location: Vertex AI region.
            model_name: Gemini model name.
            temperature: Model temperature for consistency.
            project_name: Project name for reporting.
            project_id: Project identifier for reporting.
            scan_id: Scan identifier for reporting.
            checkmarx_base_url: Checkmarx base URL for report links.
            branch: Git branch being analyzed.
            repo_url: Repository URL for logging.
            output_dir: Directory for output files.
            log_mode: ``LogMode.RICH`` (default) captures every LLM
                prompt and response verbatim in the JSONL session log;
                ``LogMode.OBSERVABILITY`` replaces content with hashes
                and lengths.
        """
        self.project_name = project_name
        self.project_id = project_id
        self.scan_id = scan_id
        self.checkmarx_base_url = checkmarx_base_url
        self.branch = branch

        # Vertex AI via the langchain-google-vertexai client (gRPC transport).
        # The caller resolves project and location via config.resolve_vertex_config.
        self._project = project
        self._location = location
        self.model_name = model_name
        self.temperature = temperature
        self._structured_llm_cache: Dict[float, object] = {}

        self.logger.info(
            f"Initializing Gemini via Vertex AI: {model_name}"
        )

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Structured JSONL session log; see docs/session-log.md for the
        # event schema.
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        self.session_logger = SessionLogger(
            log_path=log_dir / f"sast_triage_{timestamp}.jsonl",
            log_mode=log_mode,
        )

        # The per-finding flow is a LangGraph subgraph: a tool-using researcher
        # gathers evidence, structured analyst samples at varied temperature
        # produce verdicts, an adversarial critic reviews them, and the results
        # are aggregated by self-consistency.
        self.research_tools = [read_file, search_in_files, list_directory]
        research_llm = (
            self._make_llm(temperature)
            .bind_tools(self.research_tools)
            .with_config({"tags": ["session_log:mode=with_tools"]})
        )
        critic_llm = (
            self._make_llm(CRITIC_TEMPERATURE)
            .with_structured_output(CritiqueResult)
            .with_config(
                {
                    "tags": [
                        "session_log:mode=structured",
                        "session_log:schema=CritiqueResult",
                    ]
                }
            )
        )
        self.per_finding_graph = build_per_finding_graph(
            research_node=make_research_node(research_llm, self.research_tools),
            analyst_node=make_analyst_node(self._analyst_llm_for),
            critic_node=make_critic_node(critic_llm),
            aggregate_node=aggregate_node,
            session_logger=self.session_logger,
        )

        self.session_logger.emit_session_start(
            model=model_name,
            agent_config=self._agent_config_snapshot(),
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            repo_url=repo_url,
            branch=branch,
        )

        # File to store assessment results (with timestamp)
        name = project_name or "unknown"
        self.assessments_file = os.path.join(
            output_dir,
            f"findings_assessment_{name}_{timestamp}.json",
        )
        # Ensure the output directory exists before any write. io_safe keeps
        # this working on Windows when the path exceeds the 260-char MAX_PATH
        # limit; it is a no-op on POSIX.
        os.makedirs(
            io_safe(os.path.dirname(self.assessments_file) or "."),
            exist_ok=True,
        )

    @staticmethod
    def _agent_config_snapshot() -> Dict[str, Any]:
        """Constants snapshot for the ``session_start`` event."""
        return {
            "INITIAL_SAMPLES": INITIAL_SAMPLES,
            "DEFAULT_SAMPLES": DEFAULT_SAMPLES,
            "MAX_RESEARCH_ITERATIONS": MAX_RESEARCH_ITERATIONS,
            "MAX_REANALYSIS_LOOPS": MAX_REANALYSIS_LOOPS,
            "MAX_RESEARCH_STALL": MAX_RESEARCH_STALL,
            "MAX_TOOL_CALLS_PER_RESEARCH": MAX_TOOL_CALLS_PER_RESEARCH,
            "GRAPH_RECURSION_LIMIT": GRAPH_RECURSION_LIMIT,
            "ANALYST_TEMPERATURES": list(ANALYST_TEMPERATURES),
            "CRITIC_TEMPERATURE": CRITIC_TEMPERATURE,
            "CONFIDENCE_AGREEMENT_WEIGHT": CONFIDENCE_AGREEMENT_WEIGHT,
            "CONFIDENCE_THRESHOLD": CONFIDENCE_THRESHOLD,
            "NON_CONVERGENT_CONFIDENCE_CAP": NON_CONVERGENT_CONFIDENCE_CAP,
        }

    def _make_llm(self, temperature: float) -> ChatVertexAI:
        """Build a Gemini-on-Vertex client at the given temperature."""
        return ChatVertexAI(
            model_name=self.model_name,
            project=self._project,
            location=self._location,
            temperature=temperature,
            max_retries=3,
        )

    def _analyst_llm_for(self, temperature: float):
        """Structured-output analyst LLM for a temperature, cached per value."""
        if temperature not in self._structured_llm_cache:
            self._structured_llm_cache[temperature] = (
                self._make_llm(temperature)
                .with_structured_output(AnalystVerdict)
                .with_config(
                    {
                        "tags": [
                            "session_log:mode=structured",
                            "session_log:schema=AnalystVerdict",
                        ]
                    }
                )
            )
        return self._structured_llm_cache[temperature]

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
        finding_details = get_finding_details.invoke(
            {"result_hash": result_hash}
        )
        if isinstance(finding_details, dict) and "error" in finding_details:
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
            return decision

        try:
            finding = CheckmarxFinding(**finding_details)
            checklist, checklist_method = select_checklist_with_method(
                finding.queryName, finding.cweID
            )
            self.logger.debug(
                f"Selected checklist '{checklist.checklist_id}' "
                f"(method={checklist_method})"
            )

            self.session_logger.emit_finding_start(
                finding_id=result_hash,
                finding=finding.model_dump(),
                checklist_id=checklist.checklist_id,
                checklist_selection_method=checklist_method,
            )

            state = TriageState(finding=finding, checklist=checklist)
            invoke_config = self.session_logger.attach_to_graph_config(
                {"recursion_limit": GRAPH_RECURSION_LIMIT}
            )
            self.session_logger.emit_graph_invoke_start(
                finding_id=result_hash,
                recursion_limit=GRAPH_RECURSION_LIMIT,
            )
            try:
                result = await self.per_finding_graph.ainvoke(
                    state, config=invoke_config
                )
            finally:
                self.session_logger.emit_graph_invoke_end(
                    finding_id=result_hash
                )
            decision = result["verdict"]
            stop_reason = result.get("stop_reason") if isinstance(
                result, dict
            ) else None

            self.session_logger.emit_finding_complete(
                finding_id=result_hash,
                stop_reason=stop_reason,
                final_decision=decision.model_dump(),
            )
            self.logger.info(
                f"Decision: {decision.suggested_state.value} "
                f"(confidence: {decision.confidence:.2f})"
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
            self.session_logger.emit_finding_complete(
                finding_id=result_hash,
                stop_reason=None,
                final_decision=decision.model_dump(),
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
            if os.path.exists(io_safe(self.assessments_file)):
                with open(io_safe(self.assessments_file), "r") as f:
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

            with open(io_safe(self.assessments_file), "w") as f:
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
            if os.path.exists(io_safe(self.assessments_file)):
                with open(io_safe(self.assessments_file), "r") as f:
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
        with open(io_safe(self.assessments_file), "w") as f:
            json.dump(output, f, indent=2)

        # Finalize session log with summary
        self.session_logger.emit_session_end()
        self.session_logger.finalize()

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
            with open(io_safe(self.assessments_file), "w") as f:
                json.dump(error_result, f, indent=2)
            return error_result

        return triage_results
