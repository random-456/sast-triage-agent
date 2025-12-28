"""
API endpoints for session management
"""
from fastapi import APIRouter, HTTPException, status, Response
from typing import List
import logging
import csv
import io

from web_ui.models.response_models import SessionSummary
from web_ui.services.session_storage import SessionStorage
from web_ui.middleware.security import SecurityValidator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])
session_storage: SessionStorage = None


def set_session_storage(storage: SessionStorage):
    """
    Set the SessionStorage instance.

    Args:
        storage: SessionStorage instance to use
    """
    global session_storage
    session_storage = storage


@router.get("", response_model=List[SessionSummary])
async def list_sessions():
    """
    List all analysis sessions (latest 100).

    Returns:
        List of session summaries
    """
    try:
        sessions = session_storage.list_sessions()
        return sessions
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list sessions"
        )


@router.get("/{session_id}")
async def get_session(session_id: str):
    """
    Get complete session data.

    Args:
        session_id: Session ID

    Returns:
        Complete session data
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        session_data = session_storage.load_session(session_id)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )

        return session_data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get session"
        )


@router.delete("/{session_id}")
async def delete_session(session_id: str):
    """
    Delete a session.

    Args:
        session_id: Session ID

    Returns:
        Success status
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        success = session_storage.delete_session(session_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found or could not be deleted"
            )

        return {"success": True, "message": f"Session {session_id} deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete session"
        )


@router.get("/{session_id}/export/csv")
async def export_session_csv(session_id: str):
    """
    Export session results as CSV.

    Args:
        session_id: Session ID

    Returns:
        CSV file download
    """
    try:
        # Validate session ID
        SecurityValidator.validate_session_id(session_id)

        session_data = session_storage.load_session(session_id)
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found"
            )

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'resultHash',
            'queryName',
            'severity',
            'state',
            'cweID',
            'category',
            'languageName',
            'analysis_status',
            'analysis_result',
            'confidence',
            'justification',
            'user_override_decision',
            'user_override_justification',
            'checkmarx_url'
        ])

        writer.writeheader()

        for finding in session_data.get("findings", []):
            analysis = finding.get("analysis", {})
            writeback = finding.get("writeback", {})
            user_override = writeback.get("user_override", {})

            writer.writerow({
                'resultHash': finding.get('resultHash', ''),
                'queryName': finding.get('queryName', ''),
                'severity': finding.get('severity', ''),
                'state': finding.get('state', ''),
                'cweID': finding.get('cweID', ''),
                'category': finding.get('category', ''),
                'languageName': finding.get('languageName', ''),
                'analysis_status': analysis.get('status', 'pending'),
                'analysis_result': analysis.get('result', ''),
                'confidence': analysis.get('confidence', ''),
                'justification': analysis.get('justification', ''),
                'user_override_decision': user_override.get('decision', '') if user_override else '',
                'user_override_justification': user_override.get('justification', '') if user_override else '',
                'checkmarx_url': finding.get('checkmarx_url', '')
            })

        # Return CSV as download
        csv_content = output.getvalue()
        headers = {
            'Content-Disposition': f'attachment; filename="session_{session_id}_export.csv"'
        }

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers=headers
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export session"
        )
