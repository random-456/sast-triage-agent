"""Session-level coordinator for the JSONL log.

``SessionLogger`` owns the writer and the callback handler, hands out a
LangChain config that wires the callback into a graph invoke, and
provides the typed ``emit_*`` methods that the agent and the callback
handler call. The writer fills in the per-event envelope (``ts``,
``seq``, ``session_id``); callers only supply type-specific fields.

Aggregation: the logger tallies per-finding counts (LLM calls, tool
calls, per-node durations, token totals) and per-session counts so the
``finding_complete`` and ``session_end`` events carry useful summaries
without forcing consumers to re-aggregate from the raw events.
"""

from __future__ import annotations

import datetime
import hashlib
import itertools
import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from sast_triage.session_log.callback import TriageLoggingCallback
from sast_triage.session_log.events import (
    ErrorEvent,
    FindingCompleteEvent,
    FindingStartEvent,
    GraphInvokeEndEvent,
    GraphInvokeStartEvent,
    LLMCallEvent,
    LogMode,
    NodeEnterEvent,
    NodeExitEvent,
    PreprocessingCompleteEvent,
    RouteDecisionEvent,
    SessionEndEvent,
    SessionStartEvent,
    StateSnapshot,
    TokenTotals,
    ToolCallEvent,
    UsageMetadata,
)
from sast_triage.session_log.writer import JsonlEventWriter

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


class SessionLogger:
    """Owns the writer and the callback handler for one session.

    Args:
        log_path: Path of the .jsonl file to write to.
        log_mode: ``LogMode.RICH`` records full prompts and responses;
            ``LogMode.OBSERVABILITY`` records only hashes and lengths.
    """

    def __init__(self, log_path: Path, log_mode: LogMode = LogMode.RICH) -> None:
        self.log_path = Path(log_path)
        self.log_mode = log_mode
        self.session_id = str(uuid.uuid4())
        self._writer = JsonlEventWriter(self.log_path)
        self._seq = itertools.count(1)
        self._seq_lock = threading.Lock()
        self.callback_handler = TriageLoggingCallback(self)

        self._session_started_perf: Optional[float] = None
        self._session_started_iso: Optional[str] = None
        # finding_id -> perf start for graph invoke + finding lifecycle
        self._finding_perf_start: Dict[str, float] = {}
        self._invoke_perf_start: Dict[str, float] = {}

        self._finding_agg = self._fresh_finding_aggregates()
        self._session_agg = self._fresh_session_aggregates()
        self._active_finding_id: Optional[str] = None

    # ----- public lifecycle -----

    def emit_session_start(
        self,
        *,
        models: Dict[str, str],
        agent_config: Dict[str, Any],
        project_name: Optional[str] = None,
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        repo_url: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> None:
        self._session_started_perf = time.perf_counter()
        self._session_started_iso = _now_iso()
        event = SessionStartEvent(
            **self._envelope(),
            models=models,
            agent_config=agent_config,
            project_name=project_name,
            project_id=project_id,
            scan_id=scan_id,
            repo_url=repo_url,
            branch=branch,
            log_mode=self.log_mode,
            started_at=self._session_started_iso,
        )
        self._writer.write(event)

    def emit_preprocessing_complete(
        self,
        *,
        obfuscation_report: Optional[Dict[str, Any]] = None,
        masking_report: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = PreprocessingCompleteEvent(
            **self._envelope(),
            obfuscation_report=obfuscation_report,
            masking_report=masking_report,
        )
        self._writer.write(event)

    def emit_finding_start(
        self,
        *,
        finding_id: str,
        finding: Dict[str, Any],
        checklist_id: str,
        checklist_selection_method: str,
    ) -> None:
        self._finding_perf_start[finding_id] = time.perf_counter()
        self._active_finding_id = finding_id
        self._finding_agg = self._fresh_finding_aggregates()
        self.callback_handler.reset_for_finding()
        event = FindingStartEvent(
            **self._envelope(),
            finding_id=finding_id,
            finding=finding,
            checklist_id=checklist_id,
            checklist_selection_method=checklist_selection_method,  # type: ignore[arg-type]
        )
        self._writer.write(event)

    def emit_graph_invoke_start(
        self, *, finding_id: str, recursion_limit: int
    ) -> None:
        self._invoke_perf_start[finding_id] = time.perf_counter()
        event = GraphInvokeStartEvent(
            **self._envelope(),
            finding_id=finding_id,
            recursion_limit=recursion_limit,
        )
        self._writer.write(event)

    def emit_graph_invoke_end(self, *, finding_id: str) -> None:
        started = self._invoke_perf_start.pop(finding_id, time.perf_counter())
        duration_ms = (time.perf_counter() - started) * 1000.0
        event = GraphInvokeEndEvent(
            **self._envelope(),
            finding_id=finding_id,
            duration_ms=duration_ms,
        )
        self._writer.write(event)

    def emit_finding_complete(
        self,
        *,
        finding_id: str,
        stop_reason: Optional[str],
        final_decision: Dict[str, Any],
        confidence_breakdown: Optional[Dict[str, Any]] = None,
        process_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        started = self._finding_perf_start.pop(finding_id, time.perf_counter())
        total_duration_ms = (time.perf_counter() - started) * 1000.0
        agg = self._finding_agg
        event = FindingCompleteEvent(
            **self._envelope(),
            finding_id=finding_id,
            stop_reason=stop_reason,
            final_decision=final_decision,
            confidence_breakdown=confidence_breakdown,
            process_summary=process_summary,
            total_duration_ms=total_duration_ms,
            per_node_visit_counts=dict(agg["per_node_visit_counts"]),
            per_node_durations_ms=dict(agg["per_node_durations"]),
            per_node_token_totals={
                node: TokenTotals(**totals)
                for node, totals in agg["per_node_tokens"].items()
            },
            llm_calls_count=agg["llm_calls"],
            tool_calls_count=agg["tool_calls"],
            total_tokens=TokenTotals(**agg["tokens"]),
        )
        self._writer.write(event)
        self._roll_finding_into_session(final_decision)
        self._active_finding_id = None

    def emit_session_end(self) -> None:
        started = self._session_started_perf or time.perf_counter()
        total_duration_ms = (time.perf_counter() - started) * 1000.0
        agg = self._session_agg
        total = agg["findings_processed"]
        refused = agg["suggested_state_counts"].get("REFUSED", 0)
        refusal_rate = round(refused / total, 4) if total else 0.0
        event = SessionEndEvent(
            **self._envelope(),
            ended_at=_now_iso(),
            total_duration_ms=total_duration_ms,
            total_findings=total,
            suggested_state_counts=dict(agg["suggested_state_counts"]),
            refusal_rate=refusal_rate,
            total_tokens=TokenTotals(**agg["tokens"]),
            llm_calls_count=agg["llm_calls"],
            tool_calls_count=agg["tool_calls"],
        )
        self._writer.write(event)

    def finalize(self) -> None:
        """Close the writer. Idempotent."""
        self._writer.close()

    def attach_to_graph_config(
        self, config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Return a LangGraph ``ainvoke`` config with the callback
        handler attached. Merges with an existing config dict.
        """
        merged: Dict[str, Any] = dict(config or {})
        callbacks = list(merged.get("callbacks") or [])
        if self.callback_handler not in callbacks:
            callbacks.append(self.callback_handler)
        merged["callbacks"] = callbacks
        return merged

    # ----- callback-facing emits -----

    def emit_node_enter(
        self,
        *,
        node: str,
        visit_index: int,
        run_id: Optional[str],
        parent_run_id: Optional[str],
        state_snapshot: StateSnapshot,
    ) -> None:
        finding_id = self._active_finding_id
        if finding_id is None:
            return
        self._finding_agg["per_node_visit_counts"][node] = (
            self._finding_agg["per_node_visit_counts"].get(node, 0) + 1
        )
        event = NodeEnterEvent(
            **self._envelope(),
            finding_id=finding_id,
            node=node,
            visit_index=visit_index,
            run_id=run_id,
            parent_run_id=parent_run_id,
            state_snapshot=state_snapshot,
        )
        self._writer.write(event)

    def emit_node_exit(
        self,
        *,
        node: str,
        visit_index: Optional[int],
        run_id: Optional[str],
        duration_ms: float,
        state_writes: Dict[str, Any],
    ) -> None:
        finding_id = self._active_finding_id
        if finding_id is None:
            return
        self._finding_agg["per_node_durations"][node] = (
            self._finding_agg["per_node_durations"].get(node, 0.0)
            + duration_ms
        )
        event = NodeExitEvent(
            **self._envelope(),
            finding_id=finding_id,
            node=node,
            visit_index=visit_index if visit_index is not None else 0,
            run_id=run_id,
            duration_ms=duration_ms,
            state_writes=_sanitize_for_json(state_writes),
        )
        self._writer.write(event)

    def emit_llm_call(
        self,
        *,
        run_id: Optional[str],
        parent_run_id: Optional[str],
        node: Optional[str],
        model: str,
        temperature: Optional[float],
        mode: str,
        structured_schema: Optional[str],
        messages_in: List[Dict[str, Any]],
        response: Dict[str, Any],
        usage_metadata: Optional[UsageMetadata],
        duration_ms: float,
    ) -> None:
        finding_id = self._active_finding_id
        self._finding_agg["llm_calls"] += 1
        if usage_metadata is not None:
            self._add_tokens(usage_metadata, node)

        kwargs: Dict[str, Any] = {
            "model": model,
            "temperature": temperature,
            "mode": mode,  # type: ignore[arg-type]
            "structured_schema": structured_schema,
            "usage_metadata": usage_metadata,
            "duration_ms": duration_ms,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
            "node": node,
            "finding_id": finding_id,
        }
        if self.log_mode == LogMode.RICH:
            kwargs["messages_in"] = _sanitize_for_json(messages_in)
            kwargs["response"] = _sanitize_for_json(response)
        else:
            messages_blob = json.dumps(
                _sanitize_for_json(messages_in), sort_keys=True, default=str
            )
            response_blob = json.dumps(
                _sanitize_for_json(response), sort_keys=True, default=str
            )
            kwargs["messages_in_hash"] = _hash_text(messages_blob)
            kwargs["messages_in_chars"] = len(messages_blob)
            kwargs["response_hash"] = _hash_text(response_blob)
            kwargs["response_chars"] = len(response_blob)

        event = LLMCallEvent(**self._envelope(), **kwargs)
        self._writer.write(event)

    def emit_tool_call(
        self,
        *,
        run_id: Optional[str],
        parent_run_id: Optional[str],
        node: Optional[str],
        tool_name: str,
        args: Dict[str, Any],
        result: Any,
        duration_ms: float,
    ) -> None:
        finding_id = self._active_finding_id
        self._finding_agg["tool_calls"] += 1

        kwargs: Dict[str, Any] = {
            "tool_name": tool_name,
            "args": _sanitize_for_json(args),
            "duration_ms": duration_ms,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
            "node": node,
            "finding_id": finding_id,
        }
        if self.log_mode == LogMode.RICH:
            kwargs["result"] = _sanitize_for_json(result)
        else:
            result_blob = json.dumps(
                _sanitize_for_json(result), sort_keys=True, default=str
            )
            kwargs["result_hash"] = _hash_text(result_blob)
            kwargs["result_chars"] = len(result_blob)
            kwargs["result_type"] = type(result).__name__

        event = ToolCallEvent(**self._envelope(), **kwargs)
        self._writer.write(event)

    def emit_route_decision(
        self,
        *,
        from_node: str,
        to_node: str,
        predicate: str,
        state_inputs: Dict[str, Any],
    ) -> None:
        event = RouteDecisionEvent(
            **self._envelope(),
            finding_id=self._active_finding_id,
            from_node=from_node,
            to_node=to_node,
            predicate=predicate,
            state_inputs=_sanitize_for_json(state_inputs),
        )
        self._writer.write(event)

    def emit_error(
        self,
        *,
        scope: str,
        run_id: Optional[str] = None,
        node: Optional[str] = None,
        error_type: str,
        error_message: str,
        retry_attempted: Optional[bool] = None,
    ) -> None:
        event = ErrorEvent(
            **self._envelope(),
            finding_id=self._active_finding_id,
            node=node,
            run_id=run_id,
            scope=scope,  # type: ignore[arg-type]
            error_type=error_type,
            error_message=error_message,
            retry_attempted=retry_attempted,
        )
        self._writer.write(event)

    # ----- internals -----

    def _envelope(self) -> Dict[str, Any]:
        with self._seq_lock:
            seq = next(self._seq)
        return {"ts": _now_iso(), "seq": seq, "session_id": self.session_id}

    @staticmethod
    def _fresh_finding_aggregates() -> Dict[str, Any]:
        return {
            "llm_calls": 0,
            "tool_calls": 0,
            "tokens": {"input": 0, "output": 0, "total": 0},
            "per_node_durations": {},
            "per_node_visit_counts": {},
            "per_node_tokens": {},
        }

    @staticmethod
    def _fresh_session_aggregates() -> Dict[str, Any]:
        return {
            "llm_calls": 0,
            "tool_calls": 0,
            "tokens": {"input": 0, "output": 0, "total": 0},
            "findings_processed": 0,
            "suggested_state_counts": {},
        }

    def _add_tokens(
        self, usage: UsageMetadata, node: Optional[str]
    ) -> None:
        finding_tokens = self._finding_agg["tokens"]
        finding_tokens["input"] += usage.input_tokens
        finding_tokens["output"] += usage.output_tokens
        finding_tokens["total"] += usage.total_tokens
        if node:
            node_tokens = self._finding_agg["per_node_tokens"].setdefault(
                node, {"input": 0, "output": 0, "total": 0}
            )
            node_tokens["input"] += usage.input_tokens
            node_tokens["output"] += usage.output_tokens
            node_tokens["total"] += usage.total_tokens

    def _roll_finding_into_session(self, final_decision: Dict[str, Any]) -> None:
        s_agg = self._session_agg
        f_agg = self._finding_agg
        s_agg["llm_calls"] += f_agg["llm_calls"]
        s_agg["tool_calls"] += f_agg["tool_calls"]
        for k in ("input", "output", "total"):
            s_agg["tokens"][k] += f_agg["tokens"][k]
        s_agg["findings_processed"] += 1
        state = final_decision.get("suggested_state") if isinstance(final_decision, dict) else None
        if state:
            s_agg["suggested_state_counts"][state] = (
                s_agg["suggested_state_counts"].get(state, 0) + 1
            )


def _sanitize_for_json(value: Any) -> Any:
    """Best-effort coercion of LangChain/Pydantic objects to JSON-safe shapes.
    Recursively converts BaseModels via ``model_dump``; leaves primitives,
    dicts and lists alone; falls back to ``str()`` for anything else.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_json(v) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _sanitize_for_json(dump())
        except Exception:  # pragma: no cover - defensive
            pass
    return str(value)
