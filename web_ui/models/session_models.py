"""
Pydantic models for session data storage
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class AnalysisDetails(BaseModel):
    """Analysis details for a single finding"""

    status: str = Field(default="pending", description="pending, in_progress, completed, failed")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    iterations_used: Optional[int] = None
    result: Optional[str] = None  # CONFIRMED, NOT_EXPLOITABLE, REFUSED
    confidence: Optional[float] = None
    justification: Optional[str] = None
    last_action: Optional[str] = None
    conversation_log: List[Dict[str, Any]] = Field(default_factory=list)


class WritebackDetails(BaseModel):
    """Write-back details for a finding"""

    saved: bool = False
    saved_at: Optional[str] = None
    decision: Optional[str] = None
    justification: Optional[str] = None
    user_override: Optional[Dict[str, str]] = None  # {decision, justification}


class FindingData(BaseModel):
    """Complete finding data including analysis and write-back"""

    # From Checkmarx API
    resultHash: str
    category: str
    cweID: str
    languageName: str
    queryName: str
    severity: str
    state: str
    checkmarx_url: Optional[str] = None
    dataflow: List[Dict[str, Any]] = Field(default_factory=list)

    # Analysis results
    analysis: AnalysisDetails = Field(default_factory=AnalysisDetails)

    # Write-back status
    writeback: WritebackDetails = Field(default_factory=WritebackDetails)


class SessionMetadata(BaseModel):
    """Metadata for an analysis session"""

    project_name: str
    project_id: str
    scan_id: str
    branch: str
    github_url: str
    checkmarx_base_url: str
    model_name: str = "gemini-2.5-pro"
    severity_filters: List[str]
    status_filters: List[str]


class SessionStatistics(BaseModel):
    """Statistics for an analysis session"""

    total_findings: int = 0
    analyzed_count: int = 0
    pending_count: int = 0
    confirmed_count: int = 0
    not_exploitable_count: int = 0
    refused_count: int = 0
    high_confidence_count: int = 0
    avg_confidence: float = 0.0
    avg_duration_seconds: float = 0.0


class SessionData(BaseModel):
    """Complete session data structure"""

    session_id: str
    created_at: str
    updated_at: str
    status: str = "created"  # created, in_progress, completed, failed
    metadata: SessionMetadata
    findings: List[FindingData]
    statistics: SessionStatistics = Field(default_factory=SessionStatistics)
