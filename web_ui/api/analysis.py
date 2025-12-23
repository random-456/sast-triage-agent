"""
Analysis API endpoints
Start, monitor, and retry analysis tasks
"""
import logging
import os
from fastapi import APIRouter, HTTPException, status
from typing import List

from web_ui.models.request_models import StartAnalysisRequest, RetryFindingRequest
from web_ui.models.response_models import (
    StartAnalysisResponse,
    AnalysisStatusResponse
)
from web_ui.services.analysis_service import AnalysisService
from web_ui.middleware.security import SecurityValidator


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])

# Analysis service will be injected from app
analysis_service: AnalysisService = None


def set_analysis_service(service: AnalysisService):
    """
    Set the analysis service instance.

    Args:
        service: AnalysisService instance to use
    """
    global analysis_service
    analysis_service = service


@router.post("/start", response_model=StartAnalysisResponse)
async def start_analysis(request: StartAnalysisRequest):
    """
    Start triage analysis for selected findings.

    Args:
        request: Analysis request with session_id, selected_finding_hashes, model_name

    Returns:
        Analysis status response

    Raises:
        HTTPException: If analysis cannot be started
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(request.session_id)

        # Validate finding hashes
        for finding_hash in request.selected_finding_hashes:
            SecurityValidator.validate_finding_hash(finding_hash)

        # Validate model name
        model_name = request.model_name or "gemini-2.5-pro"
        SecurityValidator.validate_model_name(model_name)

        # Get Google Cloud credentials from environment
        google_cloud_project = os.getenv("PROJECT_ID")
        google_cloud_location = os.getenv("DEFAULT_LOCATION", "us-central1")

        if not google_cloud_project:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google Cloud project not configured. Set PROJECT_ID environment variable."
            )

        # Check if we can start analysis
        if not analysis_service.can_start_analysis():
            return StartAnalysisResponse(
                session_id=request.session_id,
                status="rejected",
                message="Maximum concurrent analyses reached. Please wait for an analysis to complete."
            )

        # Check if analysis is already running
        if analysis_service.is_analysis_running(request.session_id):
            return StartAnalysisResponse(
                session_id=request.session_id,
                status="rejected",
                message="Analysis already running for this session."
            )

        # Start analysis
        success = await analysis_service.start_analysis(
            session_id=request.session_id,
            selected_finding_hashes=request.selected_finding_hashes,
            model_name=model_name,
            google_cloud_project=google_cloud_project,
            google_cloud_location=google_cloud_location
        )

        if success:
            return StartAnalysisResponse(
                session_id=request.session_id,
                status="running",
                message=f"Analysis started for {len(request.selected_finding_hashes)} findings"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to start analysis"
            )

    except ValueError as e:
        logger.warning(f"Validation error starting analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error starting analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start analysis: {str(e)}"
        )


@router.get("/status/{session_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(session_id: str):
    """
    Get the current analysis status for a session.

    Args:
        session_id: Session identifier

    Returns:
        Analysis status response

    Raises:
        HTTPException: If session not found
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        # Get status
        status_str = analysis_service.get_analysis_status(session_id)

        if status_str is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )

        return AnalysisStatusResponse(
            session_id=session_id,
            status=status_str,
            active_analyses_count=analysis_service.get_active_analysis_count()
        )

    except ValueError as e:
        logger.warning(f"Validation error getting analysis status: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting analysis status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get analysis status: {str(e)}"
        )


@router.post("/retry/{session_id}", response_model=StartAnalysisResponse)
async def retry_failed_finding(session_id: str, request: RetryFindingRequest):
    """
    Retry analysis for a failed finding.

    Args:
        session_id: Session identifier
        request: Retry request with finding_hash

    Returns:
        Analysis status response

    Raises:
        HTTPException: If retry cannot be started
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        # Validate finding hash
        SecurityValidator.validate_finding_hash(request.finding_hash)

        # Get Google Cloud credentials from environment
        google_cloud_project = os.getenv("PROJECT_ID")
        google_cloud_location = os.getenv("DEFAULT_LOCATION", "us-central1")

        if not google_cloud_project:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google Cloud project not configured. Set PROJECT_ID environment variable."
            )

        # Check if we can start analysis
        if not analysis_service.can_start_analysis():
            return StartAnalysisResponse(
                session_id=session_id,
                status="rejected",
                message="Maximum concurrent analyses reached"
            )

        # Retry analysis
        success = await analysis_service.retry_failed_finding(
            session_id=session_id,
            finding_hash=request.finding_hash,
            model_name="gemini-2.5-pro",
            google_cloud_project=google_cloud_project,
            google_cloud_location=google_cloud_location
        )

        if success:
            return StartAnalysisResponse(
                session_id=session_id,
                status="running",
                message=f"Retry started for finding {request.finding_hash}"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retry analysis"
            )

    except ValueError as e:
        logger.warning(f"Validation error retrying finding: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error retrying finding: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retry analysis: {str(e)}"
        )
