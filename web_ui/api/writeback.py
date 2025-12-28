"""
Write-back API endpoints
Save triage decisions with optional user override
"""
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, status

from web_ui.models.request_models import SaveWritebackRequest
from web_ui.models.response_models import WritebackResponse
from web_ui.services.session_storage import SessionStorage
from web_ui.middleware.security import SecurityValidator


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/writeback", tags=["Writeback"])

# Session storage will be injected from app
session_storage: SessionStorage = None


def set_session_storage(storage: SessionStorage):
    """
    Set the session storage instance.

    Args:
        storage: SessionStorage instance to use
    """
    global session_storage
    session_storage = storage


@router.post("/save", response_model=WritebackResponse)
async def save_writeback(request: SaveWritebackRequest):
    """
    Save write-back decision for a finding.

    This endpoint saves the triage decision to the session JSON file.
    It does NOT actually write back to Checkmarx (placeholder functionality).

    Args:
        request: Write-back request with decision and optional user override

    Returns:
        Write-back response with success status

    Raises:
        HTTPException: If save fails
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(request.session_id)

        # Validate finding hash
        SecurityValidator.validate_finding_hash(request.finding_hash)

        # Validate decision
        if request.decision not in ["CONFIRMED", "NOT_EXPLOITABLE"]:
            raise ValueError("Decision must be CONFIRMED or NOT_EXPLOITABLE")

        # Validate user override if present
        if request.user_override:
            if request.user_override['decision'] not in ["CONFIRMED", "NOT_EXPLOITABLE"]:
                raise ValueError("User override decision must be CONFIRMED or NOT_EXPLOITABLE")
            if not request.user_override['justification'] or not request.user_override['justification'].strip():
                raise ValueError("User override justification is required")

        # Load session
        session = session_storage.load_session(request.session_id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {request.session_id} not found"
            )

        # Find the finding
        finding_data = None
        for f in session["findings"]:
            if f["resultHash"] == request.finding_hash:
                finding_data = f
                break

        if not finding_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding {request.finding_hash} not found in session"
            )

        # Check if analysis is completed
        if finding_data.get("analysis", {}).get("status") != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot save write-back for finding that is not analyzed"
            )

        # Update writeback section
        finding_data["writeback"] = {
            "saved": True,
            "saved_at": datetime.now().isoformat(),
            "decision": request.decision,
            "justification": request.justification
        }

        # Add user override if present
        if request.user_override:
            finding_data["writeback"]["user_override"] = {
                "decision": request.user_override['decision'],
                "justification": request.user_override['justification']
            }
        else:
            finding_data["writeback"]["user_override"] = None

        # Save session
        session["updated_at"] = datetime.now().isoformat()
        session_storage.save_session(session)

        logger.info(f"Saved write-back decision for finding {request.finding_hash} in session {request.session_id}")

        # Determine final decision (user override takes precedence)
        final_decision = request.user_override['decision'] if request.user_override else request.decision

        return WritebackResponse(
            success=True,
            message="Write-back decision saved successfully",
            finding_hash=request.finding_hash,
            final_decision=final_decision,
            saved_at=finding_data["writeback"]["saved_at"]
        )

    except ValueError as e:
        logger.warning(f"Validation error saving write-back: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving write-back: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save write-back: {str(e)}"
        )
