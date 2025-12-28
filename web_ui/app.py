"""
FastAPI application for SAST Triage Agent Web UI
"""
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import logging

from config import WEB_UI_HOST, WEB_UI_PORT, CERTIFICATES_CRT_FILE

# Set SSL certificate for corporate network (before any API clients are initialized)
os.environ['REQUESTS_CA_BUNDLE'] = CERTIFICATES_CRT_FILE
os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = CERTIFICATES_CRT_FILE
from web_ui.middleware.rate_limiter import RateLimiter
from web_ui.services.websocket_manager import WebSocketManager
from web_ui.services.analysis_service import AnalysisService
from web_ui.services.session_storage import SessionStorage
from web_ui.services.checkmarx_service import CheckmarxService
from web_ui.api import sessions, projects, websocket, analysis, writeback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="SAST Triage Agent Web UI",
    description="Web interface for AI-powered SAST triage",
    version="1.0.0"
)

# Configure CORS (localhost only for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"http://{WEB_UI_HOST}:{WEB_UI_PORT}",
        f"http://localhost:{WEB_UI_PORT}",
        "http://127.0.0.1:8765",
        "http://localhost:8765"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Initialize rate limiter
rate_limiter = RateLimiter()

# Initialize services
session_storage = SessionStorage()
websocket_manager = WebSocketManager()
checkmarx_service = CheckmarxService()
analysis_service = AnalysisService(session_storage, websocket_manager)

# Inject services into API modules
websocket.set_websocket_manager(websocket_manager)
analysis.set_analysis_service(analysis_service)
writeback.set_session_storage(session_storage)
sessions.set_session_storage(session_storage)
projects.set_session_storage(session_storage)
projects.set_checkmarx_service(checkmarx_service)


# Add rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    await rate_limiter.check_rate_limit(request)
    response = await call_next(request)
    return response


# Mount static files
app.mount("/static", StaticFiles(directory="web_ui/static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="web_ui/templates")

# Include routers
app.include_router(sessions.router)
app.include_router(projects.router)
app.include_router(websocket.router)
app.include_router(analysis.router)
app.include_router(writeback.router)


# Root endpoint - serve HTML UI
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    Serve the main web UI.

    Returns:
        HTML page
    """
    return templates.TemplateResponse("index.html", {"request": request})


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns:
        Status information
    """
    return {
        "status": "healthy",
        "service": "SAST Triage Agent Web UI",
        "version": "1.0.0"
    }


# Startup event
@app.on_event("startup")
async def startup_event():
    """Log startup message"""
    logger.info(f"SAST Triage Agent Web UI starting on {WEB_UI_HOST}:{WEB_UI_PORT}")
    logger.info("API Documentation available at /docs")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown message"""
    logger.info("SAST Triage Agent Web UI shutting down")
