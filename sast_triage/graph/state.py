"""State for the per-finding LangGraph triage subgraph.

`TriageState` is the single object threaded through every node (research,
analyst, critic, aggregate). It is built once per finding and accumulates
research evidence, analyst samples and critic feedback until a verdict or a
circuit-breaker stop reason is reached.
"""

from typing import List, Optional

try:
    from typing import Literal
except ImportError:  # pragma: no cover
    from typing_extensions import Literal

from pydantic import BaseModel, Field

from sast_triage.agent_models import (
    AnalystVerdict,
    CheckmarxFinding,
    CritiqueResult,
    TriageDecision,
)
from sast_triage.checklists import ChecklistDocument

StopReason = Literal["approved", "max_research", "max_reanalysis", "no_progress"]


class CodeEvidence(BaseModel):
    """A code snippet retrieved during research, with where it came from."""

    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    content: str
    relevance: str = Field(
        default="", description="Why this snippet was retrieved"
    )


class EvidenceBundle(BaseModel):
    """Accumulated code evidence for a finding (the research CODE BANK).

    Rebuilt into the research prompt each turn so the model reasons over
    structured state rather than a replayed chat history.
    """

    items: List[CodeEvidence] = Field(default_factory=list)

    def add(self, item: CodeEvidence) -> None:
        self.items.append(item)


class ToolCallRecord(BaseModel):
    """A research tool call that failed, kept so it is not retried verbatim."""

    tool_name: str
    arguments: dict = Field(default_factory=dict)
    error: str


class TriageState(BaseModel):
    """The state object threaded through the per-finding subgraph."""

    finding: CheckmarxFinding
    checklist: ChecklistDocument

    evidence: EvidenceBundle = Field(default_factory=EvidenceBundle)
    research_iterations: int = 0
    failed_tool_calls: List[ToolCallRecord] = Field(default_factory=list)

    samples: List[AnalystVerdict] = Field(default_factory=list)
    current_sample_idx: int = 0

    last_critique: Optional[CritiqueResult] = None
    reanalysis_count: int = 0

    stop_reason: Optional[StopReason] = None

    verdict: Optional[TriageDecision] = None
