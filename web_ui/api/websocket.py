"""
WebSocket API endpoints
Real-time communication for analysis progress updates
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from web_ui.services.websocket_manager import WebSocketManager
from web_ui.middleware.security import SecurityValidator


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])

# WebSocket manager will be injected from app
websocket_manager: WebSocketManager = None


def set_websocket_manager(manager: WebSocketManager):
    """
    Set the WebSocket manager instance.

    Args:
        manager: WebSocketManager instance to use
    """
    global websocket_manager
    websocket_manager = manager


@router.websocket("/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time analysis updates.

    Args:
        websocket: WebSocket connection
        session_id: Session identifier

    Protocol:
        Server -> Client:
            - {"type": "connected", "data": {...}}
            - {"type": "analysis_started", "data": {...}}
            - {"type": "agent_message", "data": {...}} - LLM response with tool calls (NEW)
            - {"type": "tool_result", "data": {...}} - Tool execution result (NEW)
            - {"type": "analysis_progress", "data": {...}} - Legacy progress summary
            - {"type": "tool_execution", "data": {...}} - Legacy tool input only
            - {"type": "analysis_complete", "data": {...}}
            - {"type": "analysis_failed", "data": {...}}
            - {"type": "batch_progress", "data": {...}}

        Client -> Server:
            - {"type": "ping", "data": {}} - Keep-alive ping

        Notes:
            - agent_message and tool_result events enable real-time conversation rendering
            - analysis_progress and tool_execution are kept for backwards compatibility
            - New UIs should use agent_message/tool_result for full conversation display
    """
    # Validate session ID
    try:
        SecurityValidator.validate_session_id(session_id)
    except ValueError as e:
        logger.warning(f"Invalid session ID for WebSocket: {e}")
        await websocket.close(code=1008, reason="Invalid session ID")
        return

    # Connect to WebSocket manager
    await websocket_manager.connect(session_id, websocket)
    logger.info(f"WebSocket connection established for session {session_id}")

    try:
        # Listen for client messages (primarily for keep-alive)
        while True:
            data = await websocket.receive_json()

            # Handle ping/pong
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong", "data": {}})

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"Error in WebSocket for session {session_id}: {e}")
    finally:
        # Disconnect from manager
        websocket_manager.disconnect(session_id, websocket)
        logger.info(f"WebSocket cleaned up for session {session_id}")
