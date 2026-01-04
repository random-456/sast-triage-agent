"""
API endpoints for projects and findings
"""
from fastapi import APIRouter, HTTPException, status
import logging

from web_ui.models.request_models import FetchFindingsRequest
from web_ui.models.response_models import (
    FetchFindingsResponse,
    FindingSummary,
    ConfigResponse,
    ModelsResponse
)
from web_ui.services.session_storage import SessionStorage
from web_ui.services.checkmarx_service import CheckmarxService
from web_ui.middleware.security import SecurityValidator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["projects"])
session_storage: SessionStorage = None
checkmarx_service: CheckmarxService = None


def set_session_storage(storage: SessionStorage):
    """
    Set the SessionStorage instance.

    Args:
        storage: SessionStorage instance to use
    """
    global session_storage
    session_storage = storage


def set_checkmarx_service(service: CheckmarxService):
    """
    Set the CheckmarxService instance.

    Args:
        service: CheckmarxService instance to use
    """
    global checkmarx_service
    checkmarx_service = service


@router.get("/settings/models", response_model=ModelsResponse)
async def get_available_models():
    """
    Get available AI models.

    Returns:
        List of available models with default
    """
    return ModelsResponse(
        models=["gemini-2.5-pro", "gemini-2.5-flash", "gemini-1.5-pro"],
        default="gemini-2.5-pro"
    )


@router.get("/settings/config", response_model=ConfigResponse)
async def get_config():
    """
    Get configuration settings.

    Returns:
        Configuration including available severities, states, etc.
    """
    return ConfigResponse(
        max_findings=1000,
        available_severities=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        available_states=[
            "TO_VERIFY",
            "CONFIRMED",
            "NOT_EXPLOITABLE",
            "PROPOSED_NOT_EXPLOITABLE",
            "URGENT"
        ],
        default_model="gemini-2.5-pro"
    )


@router.get("/projects/search")
async def search_project(name: str):
    """
    Search for a Checkmarx project by name.

    Args:
        name: Project name to search for

    Returns:
        Project information
    """
    try:
        SecurityValidator.validate_project_name(name)
        project = checkmarx_service.search_project(name)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Project '{name}' not found in Checkmarx"
            )

        return project

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching project: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search project: {str(e)}"
        )


@router.post("/findings/fetch", response_model=FetchFindingsResponse)
async def fetch_findings(request: FetchFindingsRequest):
    """
    Fetch findings from Checkmarx API and create a new session.

    Args:
        request: Fetch findings request

    Returns:
        Session ID and findings summary
    """
    logger.info(
        f"Fetching findings for project {request.project_name}, "
        f"branch {request.branch}, "
        f"severities {request.severity_filters}, "
        f"states {request.status_filters}"
    )

    try:
        # Fetch findings from Checkmarx
        project_id, scan_id, github_url, checkmarx_base_url, findings = \
            checkmarx_service.fetch_findings(
                project_name=request.project_name,
                branch=request.branch,
                severity_filters=request.severity_filters,
                state_filters=request.status_filters
            )

        if not findings:
            logger.warning(
                f"No findings found for project {request.project_name} "
                f"with filters: severities={request.severity_filters}, states={request.status_filters}"
            )

        # Create session
        session_id = session_storage.create_session(
            project_name=request.project_name,
            project_id=project_id,
            scan_id=scan_id,
            branch=request.branch,
            github_url=github_url,
            checkmarx_base_url=checkmarx_base_url,
            findings=findings,
            severity_filters=request.severity_filters,
            status_filters=request.status_filters
        )

        logger.info(f"Created session {session_id} with {len(findings)} findings")

        # Convert findings to response format
        finding_summaries = [
            FindingSummary(**{
                k: v for k, v in f.items()
                if k in FindingSummary.__fields__
            })
            for f in findings
        ]

        return FetchFindingsResponse(
            session_id=session_id,
            project_name=request.project_name,
            branch=request.branch,
            github_url=github_url,
            total_findings=len(findings),
            findings=finding_summaries
        )

    except ValueError as e:
        # Project not found or no scans
        logger.warning(f"Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error fetching findings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch findings: {str(e)}"
        )


@router.get("/findings/{session_id}")
async def get_session_findings(session_id: str):
    """
    Get findings for a session.

    Args:
        session_id: Session ID

    Returns:
        Session findings
    """
    SecurityValidator.validate_session_id(session_id)
    session_data = session_storage.load_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )

    return {
        "session_id": session_id,
        "findings": session_data.get("findings", [])
    }
