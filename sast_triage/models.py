"""
Pydantic models for SAST Triage Agent
"""

from pydantic import BaseModel, Field


class TriageDecision(BaseModel):
    """Structured output for triage decisions matching Checkmarx format"""
    findingId: str = Field(description="Unique identifier for the finding")
    assessment_result: str = Field(description="CONFIRMED, NOT_EXPLOITABLE, or REFUSED")
    assessment_confidence: float = Field(description="Confidence score between 0 and 1")
    assessment_justification: str = Field(description="Detailed justification for the decision")