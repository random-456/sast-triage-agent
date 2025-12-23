"""
Analysis Service
Orchestrates SAST triage analysis with real-time WebSocket updates
"""
import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from config import (
    CODEBASE_DIR, FINDINGS_JSON_FILE, FINDINGS_CSV_FILE,
    DEFAULT_OUTPUT_DIR, MAX_CONCURRENT_ANALYSES
)
from sast_triage.agent import SASTTriageAgent
from sast_triage.agent_tools import get_finding_details
from web_ui.services.session_storage import SessionStorage
from web_ui.services.websocket_manager import WebSocketManager


logger = logging.getLogger(__name__)


class AnalysisService:
    """
    Orchestrates SAST triage analysis with background tasks and WebSocket updates.
    """

    def __init__(
        self,
        session_storage: SessionStorage,
        websocket_manager: WebSocketManager
    ):
        self.session_storage = session_storage
        self.websocket_manager = websocket_manager

        # Track active analyses: session_id -> asyncio.Task
        self.active_analyses: Dict[str, asyncio.Task] = {}

    def can_start_analysis(self) -> bool:
        """
        Check if a new analysis can be started.

        Returns:
            True if MAX_CONCURRENT_ANALYSES limit not reached
        """
        active_count = len(self.active_analyses)
        return active_count < MAX_CONCURRENT_ANALYSES

    def is_analysis_running(self, session_id: str) -> bool:
        """
        Check if analysis is currently running for a session.

        Args:
            session_id: The session identifier

        Returns:
            True if analysis is running
        """
        return session_id in self.active_analyses

    async def start_analysis(
        self,
        session_id: str,
        selected_finding_hashes: List[str],
        model_name: str,
        google_cloud_project: str,
        google_cloud_location: str
    ) -> bool:
        """
        Start analysis for selected findings in a session.

        Args:
            session_id: The session identifier
            selected_finding_hashes: List of finding hashes to analyze
            model_name: AI model to use
            google_cloud_project: Google Cloud project ID for Vertex AI
            google_cloud_location: Google Cloud location for Vertex AI

        Returns:
            True if analysis was started successfully

        Raises:
            ValueError: If session not found or analysis already running
        """
        # Check if we can start a new analysis
        if not self.can_start_analysis():
            raise ValueError(f"Maximum concurrent analyses ({MAX_CONCURRENT_ANALYSES}) reached")

        if self.is_analysis_running(session_id):
            raise ValueError(f"Analysis already running for session {session_id}")

        # Load session
        session = self.session_storage.load_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Update session status
        session["status"] = "in_progress"
        session["updated_at"] = datetime.now().isoformat()
        self.session_storage.save_session(session)

        # Create background task
        task = asyncio.create_task(
            self._run_analysis_background(
                session_id,
                selected_finding_hashes,
                model_name,
                google_cloud_project,
                google_cloud_location
            )
        )
        self.active_analyses[session_id] = task

        logger.info(f"Started analysis for session {session_id} with {len(selected_finding_hashes)} findings")
        return True

    async def _run_analysis_background(
        self,
        session_id: str,
        selected_finding_hashes: List[str],
        model_name: str,
        google_cloud_project: str,
        google_cloud_location: str
    ):
        """
        Background task that runs the actual analysis.

        Args:
            session_id: The session identifier
            selected_finding_hashes: List of finding hashes to analyze
            model_name: AI model to use
            google_cloud_project: Google Cloud project ID
            google_cloud_location: Google Cloud location
        """
        try:
            logger.info(f"Background analysis started for session {session_id}")

            # Load session
            session = self.session_storage.load_session(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found")

            # Create progress callback that broadcasts to WebSocket
            def progress_callback(event: dict):
                """Callback that broadcasts progress events to WebSocket"""
                asyncio.create_task(
                    self.websocket_manager.broadcast(
                        session_id,
                        {"type": event["event"], "data": event}
                    )
                )

            # Initialize agent with progress callback
            agent = SASTTriageAgent(
                project=google_cloud_project,
                location=google_cloud_location,
                model_name=model_name,
                temperature=0.1,
                project_name=session["metadata"]["project_name"],
                project_id=session["metadata"].get("project_id"),
                scan_id=session["metadata"].get("scan_id"),
                checkmarx_base_url=session["metadata"].get("checkmarx_base_url"),
                branch=session["metadata"]["branch"],
                output_dir=DEFAULT_OUTPUT_DIR,
                progress_callback=progress_callback
            )

            # Analyze each selected finding
            for finding_hash in selected_finding_hashes:
                # Find the finding in session
                finding_data = None
                for f in session["findings"]:
                    if f["resultHash"] == finding_hash:
                        finding_data = f
                        break

                if not finding_data:
                    logger.warning(f"Finding {finding_hash} not found in session")
                    continue

                # Mark as in_progress
                finding_data["analysis"]["status"] = "in_progress"
                finding_data["analysis"]["started_at"] = datetime.now().isoformat()
                self.session_storage.save_session(session)

                try:
                    # Run analysis
                    logger.info(f"Analyzing finding {finding_hash}")
                    decision = await agent.analyze_single_finding(finding_hash)

                    # Update finding with results
                    finding_data["analysis"]["status"] = "completed"
                    finding_data["analysis"]["completed_at"] = datetime.now().isoformat()
                    finding_data["analysis"]["result"] = decision.assessment_result
                    finding_data["analysis"]["confidence"] = decision.assessment_confidence
                    finding_data["analysis"]["justification"] = decision.assessment_justification

                    # Calculate duration
                    if finding_data["analysis"]["started_at"]:
                        start_time = datetime.fromisoformat(finding_data["analysis"]["started_at"])
                        end_time = datetime.fromisoformat(finding_data["analysis"]["completed_at"])
                        finding_data["analysis"]["duration_seconds"] = (end_time - start_time).total_seconds()

                    # Get conversation log from agent logger
                    finding_log = agent.agent_logger.get_finding_log(finding_hash)
                    if finding_log:
                        finding_data["analysis"]["conversation_log"] = finding_log.get("conversation", [])
                        finding_data["analysis"]["iterations_used"] = finding_log.get("iteration_count", 0)

                    logger.info(f"Completed analysis for {finding_hash}: {decision.assessment_result}")

                except Exception as e:
                    logger.error(f"Error analyzing finding {finding_hash}: {e}")
                    finding_data["analysis"]["status"] = "failed"
                    finding_data["analysis"]["completed_at"] = datetime.now().isoformat()
                    finding_data["analysis"]["last_action"] = f"Error: {str(e)}"

                    # Broadcast failure event if not already sent
                    await self.websocket_manager.broadcast(
                        session_id,
                        {
                            "type": "analysis_failed",
                            "data": {
                                "finding_hash": finding_hash,
                                "error": str(e),
                                "timestamp": datetime.now().isoformat()
                            }
                        }
                    )

                # Save session after each finding
                self.session_storage.save_session(session)

            # Update session status
            session["status"] = "completed"
            session["updated_at"] = datetime.now().isoformat()

            # Recalculate statistics
            session["statistics"] = self._calculate_statistics(session["findings"])

            # Save final session
            self.session_storage.save_session(session)

            logger.info(f"Background analysis completed for session {session_id}")

        except Exception as e:
            logger.error(f"Error in background analysis for session {session_id}: {e}")

            # Update session status to failed
            try:
                session = self.session_storage.load_session(session_id)
                if session:
                    session["status"] = "failed"
                    session["updated_at"] = datetime.now().isoformat()
                    self.session_storage.save_session(session)
            except Exception as save_error:
                logger.error(f"Failed to update session status: {save_error}")

        finally:
            # Remove from active analyses
            if session_id in self.active_analyses:
                del self.active_analyses[session_id]
                logger.info(f"Removed session {session_id} from active analyses")

    def _calculate_statistics(self, findings: List[dict]) -> dict:
        """
        Calculate statistics for findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Statistics dictionary
        """
        total = len(findings)
        analyzed = sum(1 for f in findings if f.get("analysis", {}).get("status") == "completed")
        pending = sum(1 for f in findings if f.get("analysis", {}).get("status") in ["pending", "in_progress"])
        confirmed = sum(
            1 for f in findings
            if f.get("analysis", {}).get("result") == "CONFIRMED"
        )
        not_exploitable = sum(
            1 for f in findings
            if f.get("analysis", {}).get("result") == "NOT_EXPLOITABLE"
        )
        refused = sum(
            1 for f in findings
            if f.get("analysis", {}).get("result") == "REFUSED"
        )

        # Calculate averages for completed analyses
        completed_findings = [
            f for f in findings
            if f.get("analysis", {}).get("status") == "completed"
        ]

        avg_confidence = 0.0
        avg_duration = 0.0
        high_confidence_count = 0

        if completed_findings:
            confidences = [f["analysis"]["confidence"] for f in completed_findings if "confidence" in f.get("analysis", {})]
            if confidences:
                avg_confidence = sum(confidences) / len(confidences)
                high_confidence_count = sum(1 for c in confidences if c >= 0.8)

            durations = [f["analysis"]["duration_seconds"] for f in completed_findings if "duration_seconds" in f.get("analysis", {})]
            if durations:
                avg_duration = sum(durations) / len(durations)

        return {
            "total_findings": total,
            "analyzed_count": analyzed,
            "pending_count": pending,
            "confirmed_count": confirmed,
            "not_exploitable_count": not_exploitable,
            "refused_count": refused,
            "high_confidence_count": high_confidence_count,
            "avg_confidence": round(avg_confidence, 2),
            "avg_duration_seconds": round(avg_duration, 1)
        }

    async def retry_failed_finding(
        self,
        session_id: str,
        finding_hash: str,
        model_name: str,
        google_cloud_project: str,
        google_cloud_location: str
    ) -> bool:
        """
        Retry analysis for a failed finding.

        Args:
            session_id: The session identifier
            finding_hash: The finding hash to retry
            model_name: AI model to use
            google_cloud_project: Google Cloud project ID
            google_cloud_location: Google Cloud location

        Returns:
            True if retry was started successfully
        """
        # For simplicity, we'll just call start_analysis with a single finding
        return await self.start_analysis(
            session_id,
            [finding_hash],
            model_name,
            google_cloud_project,
            google_cloud_location
        )

    def get_active_analysis_count(self) -> int:
        """
        Get the number of currently active analyses.

        Returns:
            Number of active analyses
        """
        return len(self.active_analyses)

    def get_analysis_status(self, session_id: str) -> Optional[str]:
        """
        Get the analysis status for a session.

        Args:
            session_id: The session identifier

        Returns:
            "running" if analysis is active, "completed" if finished, None if not found
        """
        if session_id in self.active_analyses:
            return "running"

        # Check session file
        session = self.session_storage.load_session(session_id)
        if session:
            return session.get("status", "unknown")

        return None
