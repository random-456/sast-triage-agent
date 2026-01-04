"""
WebSocket Manager
Manages WebSocket connections for real-time analysis updates
"""
import logging
import json
from typing import Dict, List
from fastapi import WebSocket
from datetime import datetime


logger = logging.getLogger(__name__)

# Maximum WebSocket connections allowed per session
MAX_CONNECTIONS_PER_SESSION = 3


class WebSocketManager:
    """
    Manages WebSocket connections per session.

    Supports multiple connections per session (e.g., multiple browser tabs).
    """

    def __init__(self):
        # session_id -> list of WebSocket connections
        self.connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> bool:
        """
        Accept and register a new WebSocket connection for a session.

        Args:
            session_id: The session identifier
            websocket: The WebSocket connection to register

        Returns:
            True if connection was accepted, False if limit exceeded
        """
        # Check connection limit before accepting
        current_count = self.get_connection_count(session_id)
        if current_count >= MAX_CONNECTIONS_PER_SESSION:
            logger.warning(
                f"Connection limit ({MAX_CONNECTIONS_PER_SESSION}) reached for session {session_id}"
            )
            await websocket.close(code=1008, reason="Connection limit exceeded")
            return False

        await websocket.accept()

        if session_id not in self.connections:
            self.connections[session_id] = []

        self.connections[session_id].append(websocket)
        logger.info(f"WebSocket connected for session {session_id}. Total connections: {len(self.connections[session_id])}")

        # Send connection confirmation
        await self.send_to_connection(websocket, {
            "type": "connected",
            "data": {
                "session_id": session_id,
                "timestamp": datetime.now().isoformat()
            }
        })
        return True

    def disconnect(self, session_id: str, websocket: WebSocket):
        """
        Remove a WebSocket connection from the session.

        Args:
            session_id: The session identifier
            websocket: The WebSocket connection to remove
        """
        if session_id in self.connections:
            if websocket in self.connections[session_id]:
                self.connections[session_id].remove(websocket)
                logger.info(f"WebSocket disconnected for session {session_id}. Remaining connections: {len(self.connections[session_id])}")

            # Clean up empty session
            if not self.connections[session_id]:
                del self.connections[session_id]
                logger.info(f"All connections closed for session {session_id}. Session removed from manager.")

    async def broadcast(self, session_id: str, message: dict):
        """
        Broadcast a message to all connections for a session.

        Args:
            session_id: The session identifier
            message: The message dict to broadcast
        """
        if session_id not in self.connections:
            logger.debug(f"No active connections for session {session_id}. Skipping broadcast.")
            return

        # Get list of connections (copy to avoid modification during iteration)
        connections = list(self.connections[session_id])

        # Track failed connections for cleanup
        failed_connections = []

        for connection in connections:
            try:
                await self.send_to_connection(connection, message)
            except Exception as e:
                logger.warning(f"Failed to send message to connection: {e}")
                failed_connections.append(connection)

        # Clean up failed connections
        for failed_connection in failed_connections:
            self.disconnect(session_id, failed_connection)

    async def send_to_connection(self, websocket: WebSocket, message: dict):
        """
        Send a message to a specific WebSocket connection.

        Args:
            websocket: The WebSocket connection
            message: The message dict to send
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
            raise

    def get_connection_count(self, session_id: str) -> int:
        """
        Get the number of active connections for a session.

        Args:
            session_id: The session identifier

        Returns:
            Number of active connections
        """
        return len(self.connections.get(session_id, []))

    def has_connections(self, session_id: str) -> bool:
        """
        Check if a session has any active connections.

        Args:
            session_id: The session identifier

        Returns:
            True if the session has active connections
        """
        return session_id in self.connections and len(self.connections[session_id]) > 0
