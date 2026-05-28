"""LangChain callback handler that records the per-finding graph as
structured events.

The handler subscribes to LangChain's standard callbacks and emits one
``llm_call`` event per paired ``on_chat_model_start`` + ``on_llm_end``,
one ``tool_call`` event per paired ``on_tool_start`` + ``on_tool_end``,
and ``node_enter`` / ``node_exit`` events for chain starts whose name
matches a graph node. ``*_error`` callbacks emit an ``error`` event and
release the paired-start state for the same ``run_id``.

Correlation: every event records ``run_id`` and ``parent_run_id`` from
the callback. A consumer can rebuild the tree from these; LLM and tool
events are attributed to a node by walking the parent chain to the
nearest ancestor whose name is a graph node.

The handler is async-native so callbacks run inline with the chain task
and the agent's contextvars (``session_id_var``, ``finding_id_var``)
remain visible.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.outputs import LLMResult

from sast_triage.session_log.events import StateSnapshot, UsageMetadata

logger = logging.getLogger(__name__)


_NODE_NAMES = {"research", "analyst", "critic", "aggregate"}

# Tag conventions: emit these on the LLM `.with_config({"tags": [...]})`
# so the handler can label the call without inspecting LangChain
# internals. Plain LLM calls (no tag) default to mode="plain".
_TAG_MODE_PREFIX = "session_log:mode="
_TAG_SCHEMA_PREFIX = "session_log:schema="


def _state_as_dict(state: Any) -> Dict[str, Any]:
    """Coerce a LangGraph node input to a plain dict for inspection."""
    if isinstance(state, dict):
        return state
    if hasattr(state, "model_dump"):
        try:
            return state.model_dump()
        except Exception:  # pragma: no cover - defensive
            return {}
    return {}


def _snapshot_from_state(state: Any, node_name: str) -> StateSnapshot:
    """Extract counts from the state dict; include CODE BANK metadata for
    analyst/critic entries.
    """
    s = _state_as_dict(state)
    evidence = s.get("evidence") or {}
    items = evidence.get("items", []) if isinstance(evidence, dict) else []
    last_critique = s.get("last_critique")
    last_critique_decision = None
    if isinstance(last_critique, dict):
        last_critique_decision = last_critique.get("decision")

    code_bank_summary = None
    if node_name in ("analyst", "critic"):
        code_bank_summary = []
        for item in items:
            if not isinstance(item, dict):
                continue
            code_bank_summary.append(
                {
                    "file_path": item.get("file_path"),
                    "relevance": item.get("relevance"),
                    "content_chars": len(item.get("content") or ""),
                }
            )

    return StateSnapshot(
        evidence_items_count=len(items),
        failed_tool_calls_count=len(s.get("failed_tool_calls") or []),
        samples_count=len(s.get("samples") or []),
        research_iterations=int(s.get("research_iterations") or 0),
        reanalysis_count=int(s.get("reanalysis_count") or 0),
        last_critique_decision=last_critique_decision,
        code_bank_summary=code_bank_summary,
    )


def _extract_mode_and_schema(tags: Optional[List[str]]) -> Tuple[str, Optional[str]]:
    mode = "plain"
    schema: Optional[str] = None
    for tag in tags or []:
        if tag.startswith(_TAG_MODE_PREFIX):
            value = tag[len(_TAG_MODE_PREFIX):]
            if value in ("plain", "with_tools", "structured"):
                mode = value
        elif tag.startswith(_TAG_SCHEMA_PREFIX):
            schema = tag[len(_TAG_SCHEMA_PREFIX):]
    return mode, schema


def _extract_model_and_temp(serialized: Optional[Dict[str, Any]]) -> Tuple[str, Optional[float]]:
    kw = (serialized or {}).get("kwargs", {}) if serialized else {}
    model = kw.get("model_name") or kw.get("model") or "unknown"
    temp = kw.get("temperature")
    return model, temp


def _message_dumps(messages: List[BaseMessage]) -> List[Dict[str, Any]]:
    """Serialize LangChain messages to dicts. Best-effort: falls back to
    a minimal ``{type, content}`` shape if model_dump is unavailable.
    """
    dumps: List[Dict[str, Any]] = []
    for msg in messages:
        try:
            dumps.append(msg.model_dump())
        except Exception:  # pragma: no cover - defensive
            dumps.append(
                {"type": msg.__class__.__name__, "content": getattr(msg, "content", None)}
            )
    return dumps


def _response_to_dict(response: LLMResult) -> Dict[str, Any]:
    """Serialize an ``LLMResult``. The generations array carries the
    AIMessage with content and tool_calls; both are needed for replay.
    """
    try:
        return response.model_dump()
    except Exception:  # pragma: no cover - defensive
        # Fallback for older LLMResult variants.
        gens: List[List[Dict[str, Any]]] = []
        for gen_list in (response.generations or []):
            row: List[Dict[str, Any]] = []
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                row.append(
                    {
                        "text": getattr(gen, "text", ""),
                        "message": _message_dumps([msg]) if msg else None,
                    }
                )
            gens.append(row)
        return {"generations": gens, "llm_output": response.llm_output}


def _usage_from_response(response: LLMResult) -> Optional[UsageMetadata]:
    """Extract token usage from ``AIMessage.usage_metadata`` if present.
    Returns None when the field is missing (e.g. cached or stub LLMs).
    """
    try:
        gen = response.generations[0][0]
        msg = getattr(gen, "message", None)
        if msg is None:
            return None
        usage = getattr(msg, "usage_metadata", None)
        if usage is None:
            return None
        return UsageMetadata(
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            total_tokens=int(usage.get("total_tokens", 0)),
        )
    except Exception:  # pragma: no cover - defensive
        return None


class TriageLoggingCallback(AsyncCallbackHandler):
    """Async callback handler that emits session-log events.

    The handler is owned by ``SessionLogger`` and writes events through
    its public ``emit_*`` methods, never directly to a writer.
    """

    def __init__(self, session_logger) -> None:
        self._session = session_logger
        # run_id -> per-call start state
        self._llm_starts: Dict[str, Dict[str, Any]] = {}
        self._tool_starts: Dict[str, Dict[str, Any]] = {}
        # All active chain runs (for parent-chain traversal)
        # run_id -> {"parent_id": str|None, "node_name": str|None,
        #            "started_at": float, "visit_index": int|None}
        self._chains: Dict[str, Dict[str, Any]] = {}
        # node_name -> per-finding visit counter
        self._node_visit_counts: Dict[str, int] = {}

    def reset_for_finding(self) -> None:
        """Forget any per-finding state. Called by ``SessionLogger`` when
        a new finding starts so stale pair-starts do not leak across
        findings.
        """
        self._llm_starts.clear()
        self._tool_starts.clear()
        self._chains.clear()
        self._node_visit_counts.clear()

    def _find_node_for(self, parent_run_id: Optional[str]) -> Optional[str]:
        """Walk up the parent chain to the nearest tracked node."""
        current = parent_run_id
        while current is not None:
            info = self._chains.get(current)
            if info is None:
                return None
            if info.get("node_name"):
                return info["node_name"]
            current = info.get("parent_id")
        return None

    # ----- chain callbacks (LangGraph node enter/exit) -----

    async def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id,
        parent_run_id=None,
        tags=None,
        metadata=None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name")
        run_id_str = str(run_id)
        parent_id_str = str(parent_run_id) if parent_run_id else None

        is_node = name in _NODE_NAMES
        visit_index: Optional[int] = None
        if is_node:
            visit_index = self._node_visit_counts.get(name, 0)
            self._node_visit_counts[name] = visit_index + 1
            self._session.emit_node_enter(
                node=name,
                visit_index=visit_index,
                run_id=run_id_str,
                parent_run_id=parent_id_str,
                state_snapshot=_snapshot_from_state(inputs, name),
            )

        self._chains[run_id_str] = {
            "parent_id": parent_id_str,
            "node_name": name if is_node else None,
            "started_at": time.perf_counter(),
            "visit_index": visit_index,
        }

    async def on_chain_end(
        self, outputs: Any, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        info = self._chains.pop(run_id_str, None)
        if info is None or info.get("node_name") is None:
            return
        duration_ms = (time.perf_counter() - info["started_at"]) * 1000.0
        state_writes = outputs if isinstance(outputs, dict) else {}
        self._session.emit_node_exit(
            node=info["node_name"],
            visit_index=info["visit_index"],
            run_id=run_id_str,
            duration_ms=duration_ms,
            state_writes=state_writes,
        )

    async def on_chain_error(
        self, error: BaseException, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        info = self._chains.pop(run_id_str, None)
        node = info.get("node_name") if info else None
        self._session.emit_error(
            scope="chain",
            run_id=run_id_str,
            node=node,
            error_type=type(error).__name__,
            error_message=str(error),
        )

    # ----- LLM callbacks -----

    async def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id,
        parent_run_id=None,
        tags=None,
        metadata=None,
        **kwargs: Any,
    ) -> None:
        run_id_str = str(run_id)
        parent_id_str = str(parent_run_id) if parent_run_id else None
        mode, schema = _extract_mode_and_schema(tags)
        model, temperature = _extract_model_and_temp(serialized)
        flat_messages = messages[0] if messages else []
        self._llm_starts[run_id_str] = {
            "started_at": time.perf_counter(),
            "messages": flat_messages,
            "model": model,
            "temperature": temperature,
            "mode": mode,
            "structured_schema": schema,
            "parent_id": parent_id_str,
            "node": self._find_node_for(parent_id_str),
        }

    async def on_llm_end(
        self, response: LLMResult, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        start = self._llm_starts.pop(run_id_str, None)
        if start is None:
            return
        duration_ms = (time.perf_counter() - start["started_at"]) * 1000.0
        messages_in = _message_dumps(start["messages"])
        response_dict = _response_to_dict(response)
        usage = _usage_from_response(response)
        self._session.emit_llm_call(
            run_id=run_id_str,
            parent_run_id=start["parent_id"],
            node=start["node"],
            model=start["model"],
            temperature=start["temperature"],
            mode=start["mode"],
            structured_schema=start["structured_schema"],
            messages_in=messages_in,
            response=response_dict,
            usage_metadata=usage,
            duration_ms=duration_ms,
        )

    async def on_llm_error(
        self, error: BaseException, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        start = self._llm_starts.pop(run_id_str, None)
        node = start.get("node") if start else None
        self._session.emit_error(
            scope="llm",
            run_id=run_id_str,
            node=node,
            error_type=type(error).__name__,
            error_message=str(error),
            retry_attempted=True,
        )

    # ----- Tool callbacks -----

    async def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id,
        parent_run_id=None,
        tags=None,
        metadata=None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        run_id_str = str(run_id)
        parent_id_str = str(parent_run_id) if parent_run_id else None
        tool_name = (serialized or {}).get("name") or kwargs.get("name") or "unknown"
        # Prefer the dict ``inputs`` (newer LangChain versions). Fall back
        # to a single-key dict from ``input_str`` for older shapes.
        args = inputs if isinstance(inputs, dict) else {"input": input_str}
        self._tool_starts[run_id_str] = {
            "started_at": time.perf_counter(),
            "tool_name": tool_name,
            "args": args,
            "parent_id": parent_id_str,
            "node": self._find_node_for(parent_id_str),
        }

    async def on_tool_end(
        self, output: Any, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        start = self._tool_starts.pop(run_id_str, None)
        if start is None:
            return
        duration_ms = (time.perf_counter() - start["started_at"]) * 1000.0
        self._session.emit_tool_call(
            run_id=run_id_str,
            parent_run_id=start["parent_id"],
            node=start["node"],
            tool_name=start["tool_name"],
            args=start["args"],
            result=output,
            duration_ms=duration_ms,
        )

    async def on_tool_error(
        self, error: BaseException, *, run_id, parent_run_id=None, **kwargs: Any
    ) -> None:
        run_id_str = str(run_id)
        start = self._tool_starts.pop(run_id_str, None)
        node = start.get("node") if start else None
        self._session.emit_error(
            scope="tool",
            run_id=run_id_str,
            node=node,
            error_type=type(error).__name__,
            error_message=str(error),
        )
