"""
Pydantic models for SAST Triage Agent.

Separates a finding's raw classification (`is_vulnerable`) from its derived
disposition (`suggested_state`). All output is advisory: the tool reads from
Checkmarx One but never writes triage state back.
"""

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class SampleVote(BaseModel):
    """One surviving voting sample, summarized for the confidence breakdown.

    Structural counts only (no content), so it is identical in rich and
    observability log modes.
    """

    is_vulnerable: Optional[bool] = Field(
        description="The sample's classification: True, False or None"
    )
    self_confidence: float = Field(
        ge=0.0, le=1.0, description="The sample's pre-calibration self-report"
    )
    temperature: Optional[float] = Field(
        default=None, description="Sampling temperature that produced the sample"
    )
    n_citations: int = Field(ge=0, description="Number of citation lines")
    n_evidence_refs: int = Field(ge=0, description="Number of evidence references")


class ConfidenceBreakdown(BaseModel):
    """The exact inputs that produced a finding's calibrated confidence.

    Logged on ``finding_complete`` so the viewer can explain the number
    without reimplementing the aggregator. ``final_confidence`` equals
    ``TriageDecision.confidence``.
    """

    agreement_rate: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Vote agreement; None below the corroboration floor",
    )
    evidence_strength: float = Field(
        ge=0.0, le=1.0, description="0..1 grounding proxy from files and citations"
    )
    agreement_weight: float = Field(
        ge=0.0, le=1.0, description="CONFIDENCE_AGREEMENT_WEIGHT at compute time"
    )
    raw_confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence before the circuit-breaker cap"
    )
    cap_applied: bool = Field(
        description="Whether the non-convergent dismissal cap lowered confidence"
    )
    cap_value: float = Field(
        ge=0.0, le=1.0, description="NON_CONVERGENT_CONFIDENCE_CAP"
    )
    final_confidence: float = Field(
        ge=0.0, le=1.0, description="Final confidence; equals the decision's"
    )
    threshold: float = Field(
        ge=0.0, le=1.0, description="CONFIDENCE_THRESHOLD for the disposition"
    )
    sample_votes: List[SampleVote] = Field(
        default_factory=list, description="One entry per surviving voting sample"
    )


# Field names below mirror the Checkmarx One result payload (camelCase) on
# purpose, matching TriageDecision.resultHash and the dict keys the ingestion
# layer already uses. `extra="allow"` keeps the full payload lossless: we
# validate the fields we depend on and carry the rest through untouched.


class DataflowNode(BaseModel):
    """One node in a Checkmarx finding's dataflow (source to sink path)."""

    model_config = ConfigDict(extra="allow")

    fileName: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    method: Optional[str] = None
    name: Optional[str] = None
    fullName: Optional[str] = None
    domType: Optional[str] = None


class CheckmarxFinding(BaseModel):
    """A SAST finding read from Checkmarx One.

    Validated at the ingestion boundary so the rest of the pipeline works
    against a typed object rather than a raw dict. Only `resultHash` is
    required: selection and prompting already tolerate missing metadata.
    """

    model_config = ConfigDict(extra="allow")

    resultHash: str
    queryName: Optional[str] = None
    cweID: Optional[str] = None
    severity: Optional[str] = None
    state: Optional[str] = None
    category: Optional[str] = None
    languageName: Optional[str] = None
    dataflow: List[DataflowNode] = Field(default_factory=list)

    @field_validator("cweID", mode="before")
    @classmethod
    def _coerce_cwe_to_str(cls, value: Union[int, str, None]) -> Optional[str]:
        # Reason: Checkmarx sends cweID as either an int (328) or a string
        # ("328"); normalize to str so downstream CWE handling has one type.
        return str(value) if value is not None else None


class AnalystVerdict(BaseModel):
    """One analyst sample's classification of a finding.

    Self-consistency runs several of these per finding; the aggregator votes
    over `is_vulnerable` and weights `confidence` by agreement. `confidence`
    here is the analyst's self-report, before calibration.
    """

    is_vulnerable: Optional[bool] = Field(
        description="True if exploitable, False if not, None if undecided"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Self-reported confidence, pre-calibration"
    )
    reasoning: str = Field(description="The analyst's justification")
    citation_lines: List[str] = Field(
        default_factory=list,
        description="file:line citation for each claim made",
    )
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Files or evidence items the analyst relied on",
    )
    sample_temperature: Optional[float] = Field(
        default=None, description="Sampling temperature that produced this verdict"
    )


class CritiqueDecision(str, Enum):
    """The critic's routing decision for an analyst verdict."""

    APPROVED = "APPROVED"
    NEEDS_MORE_RESEARCH = "NEEDS_MORE_RESEARCH"
    REANALYZE = "REANALYZE"


class CritiqueResult(BaseModel):
    """The critic LLM's structured assessment of an analyst verdict.

    `weakest_point` is mandatory even on APPROVED: "looks fine to me" is not a
    valid critique. `gaps`/`required_information` drive a research loop;
    `reanalysis_feedback` drives a reanalysis loop.
    """

    decision: CritiqueDecision
    rationale: str
    weakest_point: str = Field(
        description="The single weakest part of the verdict; required always"
    )
    gaps: List[str] = Field(default_factory=list)
    required_information: List[str] = Field(default_factory=list)
    reanalysis_feedback: str = ""
    citation_lines: List[str] = Field(default_factory=list)


class CriticConfig(BaseModel):
    """Critic loop tuning. Defaults match doc 05; calibrated later on data."""

    temperature: float = 0.6
    max_research_loops: int = 2
    max_reanalysis_loops: int = 2
