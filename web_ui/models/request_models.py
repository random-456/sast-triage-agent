"""
Pydantic models for API requests
"""
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from web_ui.middleware.security import SecurityValidator


class FetchFindingsRequest(BaseModel):
    """Request model for fetching findings from Checkmarx"""

    project_name: str = Field(..., description="Checkmarx project name")
    branch: str = Field(..., description="Git branch name")
    severity_filters: List[str] = Field(
        default=["HIGH", "MEDIUM"],
        description="List of severities to filter"
    )
    status_filters: List[str] = Field(
        default=["TO_VERIFY"],
        description="List of states to filter (note: Checkmarx uses 'state')"
    )

    @validator('project_name')
    def validate_project_name(cls, v):
        return SecurityValidator.validate_project_name(v)

    @validator('branch')
    def validate_branch(cls, v):
        return SecurityValidator.validate_branch_name(v)

    @validator('severity_filters')
    def validate_severities(cls, v):
        return SecurityValidator.validate_severities(v)

    @validator('status_filters')
    def validate_states(cls, v):
        return SecurityValidator.validate_states(v)


class StartAnalysisRequest(BaseModel):
    """Request model for starting triage analysis"""

    session_id: str = Field(..., description="Session ID")
    selected_finding_hashes: List[str] = Field(
        ...,
        description="List of finding hashes to analyze"
    )
    model_name: Optional[str] = Field(
        default="gemini-2.5-pro",
        description="AI model to use for analysis"
    )

    @validator('session_id')
    def validate_session_id(cls, v):
        return SecurityValidator.validate_session_id(v)

    @validator('selected_finding_hashes')
    def validate_finding_hashes(cls, v):
        if not v:
            raise ValueError("At least one finding must be selected")
        return [SecurityValidator.validate_finding_hash(h) for h in v]

    @validator('model_name')
    def validate_model_name(cls, v):
        if v:
            return SecurityValidator.validate_model_name(v)
        return v


class RetryFindingRequest(BaseModel):
    """Request model for retrying a failed finding"""

    finding_hash: str = Field(..., description="Finding hash to retry")

    @validator('finding_hash')
    def validate_finding_hash(cls, v):
        return SecurityValidator.validate_finding_hash(v)


class SaveWritebackRequest(BaseModel):
    """Request model for saving write-back decision"""

    session_id: str = Field(..., description="Session ID")
    finding_hash: str = Field(..., description="Finding hash")
    decision: str = Field(..., description="Agent decision (CONFIRMED/NOT_EXPLOITABLE)")
    justification: str = Field(..., description="Agent justification")
    user_override: Optional[dict] = Field(
        default=None,
        description="Optional user override {decision, justification}"
    )

    @validator('session_id')
    def validate_session_id(cls, v):
        return SecurityValidator.validate_session_id(v)

    @validator('finding_hash')
    def validate_finding_hash(cls, v):
        return SecurityValidator.validate_finding_hash(v)

    @validator('decision')
    def validate_decision(cls, v):
        if v not in ["CONFIRMED", "NOT_EXPLOITABLE"]:
            raise ValueError("Decision must be CONFIRMED or NOT_EXPLOITABLE")
        return v

    @validator('user_override')
    def validate_user_override(cls, v):
        if v:
            if 'decision' not in v or 'justification' not in v:
                raise ValueError("user_override must contain decision and justification")
            if v['decision'] not in ["CONFIRMED", "NOT_EXPLOITABLE"]:
                raise ValueError("Override decision must be CONFIRMED or NOT_EXPLOITABLE")

            # Sanitize justification to prevent XSS
            v['justification'] = SecurityValidator.sanitize_html(v['justification'])
        return v
