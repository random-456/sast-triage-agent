"""
Pydantic models for API responses
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from web_ui.middleware.security import SecurityValidator


class FindingSummary(BaseModel):
    """Summary of a single finding"""

    resultHash: str
    category: str
    cweID: str
    languageName: str
    queryName: str
    severity: str
    state: str = "TO_VERIFY"  # Default if not provided
    checkmarx_url: Optional[str] = None

    @field_validator('queryName', 'category', 'languageName', mode='before')
    @classmethod
    def sanitize_text_fields(cls, v):
        return SecurityValidator.sanitize_html(v) if v else ""

    @field_validator('cweID', mode='before')
    @classmethod
    def convert_cweid_to_string(cls, v):
        """Convert cweID to string if it's an integer."""
        return str(v) if v is not None else ""


class FetchFindingsResponse(BaseModel):
    """Response model for fetching findings"""

    session_id: str
    project_name: str
    branch: str
    github_url: Optional[str] = None
    total_findings: int
    findings: List[FindingSummary]


class SessionSummary(BaseModel):
    """Summary of an analysis session for listing"""

    session_id: str
    project_name: str
    branch: str
    created_at: str
    total_findings: int
    analyzed_count: int
    confirmed_count: int
    not_exploitable_count: int
    refused_count: int
    status: str  # created, in_progress, completed, failed


class AnalysisStatusResponse(BaseModel):
    """Response model for analysis status"""

    session_id: str
    status: str  # running, completed, failed
    progress: Dict[str, Any]  # {current: int, total: int, findings: {hash: status}}
    results: List[Dict[str, Any]]  # List of completed findings with results


class StartAnalysisResponse(BaseModel):
    """Response model for starting analysis"""

    analysis_id: str
    status: str  # running
    message: str = "Analysis started successfully"


class ConfigResponse(BaseModel):
    """Response model for configuration"""

    max_findings: int = 1000
    available_severities: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    available_states: List[str] = [
        "TO_VERIFY",
        "CONFIRMED",
        "NOT_EXPLOITABLE",
        "PROPOSED_NOT_EXPLOITABLE",
        "URGENT"
    ]
    default_model: str = "gemini-2.5-pro"


class ModelsResponse(BaseModel):
    """Response model for available models"""

    models: List[str] = ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-1.5-pro"]
    default: str = "gemini-2.5-pro"


class WritebackResponse(BaseModel):
    """Response model for write-back operation"""

    success: bool
    message: str
    finding_hash: str


class ErrorResponse(BaseModel):
    """Standard error response"""

    detail: str
    error_type: Optional[str] = None
