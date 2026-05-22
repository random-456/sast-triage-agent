"""
Pydantic models for SAST Triage Agent.

Separates a finding's raw classification (`is_vulnerable`) from its derived
disposition (`suggested_state`). All output is advisory: the tool reads from
Checkmarx One but never writes triage state back.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from config import CONFIDENCE_THRESHOLD


class SuggestedState(str, Enum):
    """Advisory disposition derived from classification and confidence."""

    CONFIRMED = "CONFIRMED"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    PROPOSED_NOT_EXPLOITABLE = "PROPOSED_NOT_EXPLOITABLE"
    REFUSED = "REFUSED"


def derive_state(
    is_vulnerable: Optional[bool], confidence: float
) -> SuggestedState:
    """Map a classification and confidence to an advisory disposition.

    Args:
        is_vulnerable: True (exploitable), False (not exploitable) or None
            (the agent could not decide).
        confidence: Calibrated confidence in the range 0.0-1.0.

    Returns:
        The disposition. A positive is always surfaced as CONFIRMED
        regardless of confidence: missing a real vulnerability is the worst
        outcome. A low-confidence dismissal is routed to
        PROPOSED_NOT_EXPLOITABLE for human attention rather than silently
        marked NOT_EXPLOITABLE.
    """
    if is_vulnerable is None:
        return SuggestedState.REFUSED
    if is_vulnerable:
        return SuggestedState.CONFIRMED
    if confidence >= CONFIDENCE_THRESHOLD:
        return SuggestedState.NOT_EXPLOITABLE
    return SuggestedState.PROPOSED_NOT_EXPLOITABLE


class TriageDecision(BaseModel):
    """Structured per-finding triage output.

    `is_vulnerable` + `confidence` are the classification; `suggested_state`
    is the disposition derived from them. `agreement_rate` and `sample_count`
    are diagnostics populated by the self-consistency layer when present.
    """

    resultHash: str = Field(
        description="Unique result hash identifier from Checkmarx"
    )
    is_vulnerable: Optional[bool] = Field(
        description="True if exploitable, False if not, None if undecided"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )
    suggested_state: SuggestedState = Field(
        description="Advisory disposition derived from the classification"
    )
    justification: str = Field(
        description="Detailed justification for the decision"
    )
    agreement_rate: Optional[float] = Field(
        default=None, description="Self-consistency agreement rate diagnostic"
    )
    sample_count: Optional[int] = Field(
        default=None, description="Number of self-consistency samples"
    )
