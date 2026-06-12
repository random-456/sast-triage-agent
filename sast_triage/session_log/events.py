"""Pydantic event models for the session log.

The log is a JSONL stream of typed events. Every event carries a small
envelope (``v``, ``type``, ``ts``, ``seq``, ``session_id``) plus
type-specific fields. ``v`` is versioned per type, so individual event
shapes can evolve without forcing a global bump.

The discriminated union ``SessionLogEvent`` makes parsing trivial via
``TypeAdapter(SessionLogEvent).validate_json(line)`` for downstream
tools (replay harness, future viewer).
"""

from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class LogMode(str, Enum):
    """Whether to capture full prompts/responses (``rich``) or only
    hashes and counters (``observability``).
    """

    RICH = "rich"
    OBSERVABILITY = "observability"


class EventType(str, Enum):
    """Discriminator values for the event union."""

    SESSION_START = "session_start"
    PREPROCESSING_COMPLETE = "preprocessing_complete"
    FINDING_START = "finding_start"
    GRAPH_INVOKE_START = "graph_invoke_start"
    NODE_ENTER = "node_enter"
    NODE_EXIT = "node_exit"
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    ROUTE_DECISION = "route_decision"
    ERROR = "error"
    GRAPH_INVOKE_END = "graph_invoke_end"
    FINDING_COMPLETE = "finding_complete"
    SESSION_END = "session_end"


class _EventBase(BaseModel):
    """Shared envelope. Subclasses pin ``type`` to a ``Literal``."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    ts: str = Field(description="ISO-8601 timestamp with microseconds (UTC)")
    seq: int = Field(description="Monotonic per-session sequence number")
    session_id: str


class UsageMetadata(BaseModel):
    """Token usage as reported by ``AIMessage.usage_metadata``."""

    input_tokens: int
    output_tokens: int
    total_tokens: int


class TokenTotals(BaseModel):
    """Aggregated token counts for a finding or session."""

    input: int = 0
    output: int = 0
    total: int = 0


class StateSnapshot(BaseModel):
    """Counts captured on ``node_enter`` so the viewer can show where
    the graph is in a finding without parsing every prior event.

    ``code_bank_summary`` is populated only for analyst and critic
    entries; it lists the bank items the LLM is about to see, without
    duplicating the content (the content is in the next ``llm_call``).
    """

    model_config = ConfigDict(extra="forbid")

    evidence_items_count: int = 0
    failed_tool_calls_count: int = 0
    samples_count: int = 0
    research_iterations: int = 0
    reanalysis_count: int = 0
    last_critique_decision: Optional[str] = None
    code_bank_summary: Optional[List[Dict[str, Any]]] = None


class SessionStartEvent(_EventBase):
    type: Literal["session_start"] = "session_start"
    v: int = 2
    # Per-node model names, keyed by node ("research", "analyst", "critic").
    # v1 logs carried a single ``model`` string instead.
    models: Dict[str, str]
    agent_config: Dict[str, Any]
    project_name: Optional[str] = None
    project_id: Optional[str] = None
    scan_id: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    log_mode: LogMode
    started_at: str


class PreprocessingCompleteEvent(_EventBase):
    type: Literal["preprocessing_complete"] = "preprocessing_complete"
    v: int = 1
    obfuscation_report: Optional[Dict[str, Any]] = None
    masking_report: Optional[Dict[str, Any]] = None


class FindingStartEvent(_EventBase):
    type: Literal["finding_start"] = "finding_start"
    v: int = 1
    finding_id: str
    finding: Dict[str, Any]
    checklist_id: str
    checklist_selection_method: Literal["query_name", "cwe", "default"]


class GraphInvokeStartEvent(_EventBase):
    type: Literal["graph_invoke_start"] = "graph_invoke_start"
    v: int = 1
    finding_id: str
    recursion_limit: int


class NodeEnterEvent(_EventBase):
    type: Literal["node_enter"] = "node_enter"
    v: int = 1
    finding_id: str
    node: str
    visit_index: int
    run_id: Optional[str] = None
    parent_run_id: Optional[str] = None
    state_snapshot: StateSnapshot


class NodeExitEvent(_EventBase):
    type: Literal["node_exit"] = "node_exit"
    v: int = 1
    finding_id: str
    node: str
    visit_index: int
    run_id: Optional[str] = None
    duration_ms: float
    state_writes: Dict[str, Any]


class LLMCallEvent(_EventBase):
    """One LLM call. Paired from ``on_chat_model_start`` and ``on_llm_end``.

    In rich mode ``messages_in`` and ``response`` carry the literal
    LangChain payloads needed for replay. In observability mode they
    are replaced by content hashes and lengths.
    """

    type: Literal["llm_call"] = "llm_call"
    v: int = 1
    finding_id: Optional[str] = None
    node: Optional[str] = None
    run_id: Optional[str] = None
    parent_run_id: Optional[str] = None
    model: str
    temperature: Optional[float] = None
    mode: Literal["plain", "with_tools", "structured"]
    structured_schema: Optional[str] = None
    # Rich mode.
    messages_in: Optional[List[Dict[str, Any]]] = None
    response: Optional[Dict[str, Any]] = None
    # Observability mode.
    messages_in_hash: Optional[str] = None
    messages_in_chars: Optional[int] = None
    response_hash: Optional[str] = None
    response_chars: Optional[int] = None
    # Always recorded.
    usage_metadata: Optional[UsageMetadata] = None
    duration_ms: float


class ToolCallEvent(_EventBase):
    """One tool call. Paired from ``on_tool_start`` and ``on_tool_end``."""

    type: Literal["tool_call"] = "tool_call"
    v: int = 1
    finding_id: Optional[str] = None
    node: Optional[str] = None
    run_id: Optional[str] = None
    parent_run_id: Optional[str] = None
    tool_name: str
    args: Dict[str, Any]
    # Rich mode.
    result: Optional[Any] = None
    # Observability mode.
    result_hash: Optional[str] = None
    result_chars: Optional[int] = None
    result_type: Optional[str] = None
    # Always recorded.
    duration_ms: float


class RouteDecisionEvent(_EventBase):
    type: Literal["route_decision"] = "route_decision"
    v: int = 1
    finding_id: Optional[str] = None
    from_node: str
    to_node: str
    predicate: str
    state_inputs: Dict[str, Any]


class ErrorEvent(_EventBase):
    type: Literal["error"] = "error"
    v: int = 1
    finding_id: Optional[str] = None
    node: Optional[str] = None
    run_id: Optional[str] = None
    scope: Literal["llm", "tool", "chain", "other"]
    error_type: str
    error_message: str
    retry_attempted: Optional[bool] = None


class GraphInvokeEndEvent(_EventBase):
    type: Literal["graph_invoke_end"] = "graph_invoke_end"
    v: int = 1
    finding_id: str
    duration_ms: float


class FindingCompleteEvent(_EventBase):
    type: Literal["finding_complete"] = "finding_complete"
    v: int = 2
    finding_id: str
    stop_reason: Optional[str] = None
    final_decision: Dict[str, Any]
    confidence_breakdown: Optional[Dict[str, Any]] = None
    process_summary: Optional[Dict[str, Any]] = None
    total_duration_ms: float
    per_node_visit_counts: Dict[str, int] = Field(default_factory=dict)
    per_node_durations_ms: Dict[str, float] = Field(default_factory=dict)
    per_node_token_totals: Dict[str, TokenTotals] = Field(default_factory=dict)
    llm_calls_count: int = 0
    tool_calls_count: int = 0
    total_tokens: TokenTotals = Field(default_factory=TokenTotals)


class SessionEndEvent(_EventBase):
    type: Literal["session_end"] = "session_end"
    v: int = 1
    ended_at: str
    total_duration_ms: float
    total_findings: int
    suggested_state_counts: Dict[str, int] = Field(default_factory=dict)
    refusal_rate: float = 0.0
    total_tokens: TokenTotals = Field(default_factory=TokenTotals)
    llm_calls_count: int = 0
    tool_calls_count: int = 0


SessionLogEvent = Annotated[
    Union[
        SessionStartEvent,
        PreprocessingCompleteEvent,
        FindingStartEvent,
        GraphInvokeStartEvent,
        NodeEnterEvent,
        NodeExitEvent,
        LLMCallEvent,
        ToolCallEvent,
        RouteDecisionEvent,
        ErrorEvent,
        GraphInvokeEndEvent,
        FindingCompleteEvent,
        SessionEndEvent,
    ],
    Field(discriminator="type"),
]
"""Discriminated union of every event type. Use with
``pydantic.TypeAdapter(SessionLogEvent).validate_json(line)`` to parse
one line of a session log.
"""
