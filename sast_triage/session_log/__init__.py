"""Structured JSONL session log for the v3 triage subgraph.

Public API:

- ``SessionLogger`` -- top-level coordinator. Owns a writer and a
  callback handler. The agent creates one per run.
- ``LogMode`` -- ``RICH`` (default) records full LLM prompts and
  responses; ``OBSERVABILITY`` records hashes and lengths only.
- ``wrap_route`` -- decorator that turns the three pure routing
  functions in ``sast_triage/graph/routing.py`` into ``route_decision``
  emitters without changing their behavior.
- ``TriageLoggingCallback`` -- the ``AsyncCallbackHandler`` subclass
  the session logger attaches to the per-finding graph invocation.

Event models live in ``events`` for downstream tooling and the future
viewer:

```python
from sast_triage.session_log.events import SessionLogEvent
from pydantic import TypeAdapter

adapter = TypeAdapter(SessionLogEvent)
for line in open(log_path):
    event = adapter.validate_json(line)
```
"""

from sast_triage.session_log.callback import TriageLoggingCallback
from sast_triage.session_log.events import (
    EventType,
    LogMode,
    SessionLogEvent,
)
from sast_triage.session_log.routing_hooks import wrap_route
from sast_triage.session_log.session import SessionLogger

__all__ = [
    "EventType",
    "LogMode",
    "SessionLogEvent",
    "SessionLogger",
    "TriageLoggingCallback",
    "wrap_route",
]
