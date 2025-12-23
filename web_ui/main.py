#!/usr/bin/env python3
"""
Web UI entry point for SAST Triage Agent

Usage:
    python -m web_ui.main
"""
import uvicorn
from config import WEB_UI_HOST, WEB_UI_PORT

if __name__ == "__main__":
    uvicorn.run(
        "web_ui.app:app",
        host=WEB_UI_HOST,
        port=WEB_UI_PORT,
        reload=True,  # Enable auto-reload for development
        log_level="info"
    )
