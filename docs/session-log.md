# Session Log Event Schema

Every triage session writes a JSONL event stream to
`logs/sast_triage_<timestamp>.jsonl`. One JSON object per line,
append-only, flushed per write so a crash leaves a clean prefix of
complete events. This document is the reference for downstream tooling:
the replay harness, the [Session Log Viewer](session-log-viewer.md) under
`viewer/`, and ad-hoc analysis scripts.

## File shape

```
logs/
    sast_triage_20260528_120000.jsonl
        {"type":"session_start","v":2,"ts":"...","seq":1,"session_id":"...",...}
        {"type":"preprocessing_complete","v":1,"ts":"...","seq":2,...}
        {"type":"finding_start","v":1,...}
        ...
        {"type":"session_end","v":1,...}
```

A single session_id appears on every line of one file. The file may
contain events from one or many findings, in chronological emit order.

## Envelope

Every event carries these five fields:

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | Discriminator. One of the 13 values in the table below. |
| `v` | int | Per-type schema version. Starts at 1; bumped per type when its shape changes. |
| `ts` | string | ISO-8601 UTC timestamp with microseconds. |
| `seq` | int | Monotonic per-session sequence number. Strictly increasing across the file. |
| `session_id` | string | UUID4 for this session. Identical on every line of one file. |

Per-finding events additionally carry `finding_id` (the Checkmarx
result hash). Node, LLM and tool events also carry `run_id` and (when
nested) `parent_run_id` so consumers can rebuild the natural tree.

## Event types

13 stable types. The discriminated union `SessionLogEvent` in
`sast_triage/session_log/events.py` parses any line to the concrete
Pydantic model.

### Session lifecycle

| Type | Emitted | Key fields |
|------|---------|-----------|
| `session_start` | At agent construction | `models` (per-node model names keyed by `research`, `analyst`, `critic`; schema `v` is `2`, v1 carried a single `model` string), `agent_config` (constants snapshot incl. `INITIAL_SAMPLES`, `DEFAULT_SAMPLES`, `MAX_RESEARCH_ITERATIONS`, `MAX_REANALYSIS_LOOPS`, `MAX_TOOL_CALLS_PER_RESEARCH`, `GRAPH_RECURSION_LIMIT`, `ANALYST_TEMPERATURES`, `CRITIC_TEMPERATURE`, `CONFIDENCE_AGREEMENT_WEIGHT`, `CONFIDENCE_THRESHOLD`), `project_name`, `project_id`, `scan_id`, `repo_url`, `branch`, `log_mode`, `started_at` |
| `preprocessing_complete` | After the preprocessing pipeline | `obfuscation_report`, `masking_report` |
| `session_end` | After all findings | `ended_at`, `total_duration_ms`, `total_findings`, `suggested_state_counts`, `refusal_rate`, `total_tokens` (input / output / total), `llm_calls_count`, `tool_calls_count` |

### Per-finding lifecycle

| Type | Emitted | Key fields |
|------|---------|-----------|
| `finding_start` | Before graph invoke | `finding_id`, `finding` (full `CheckmarxFinding` dump), `checklist_id`, `checklist_selection_method` (one of `"query_name"`, `"cwe"`, `"default"`) |
| `graph_invoke_start` | Just before `per_finding_graph.ainvoke` | `finding_id`, `recursion_limit` |
| `graph_invoke_end` | After `ainvoke` returns | `finding_id`, `duration_ms` |
| `finding_complete` (v2) | After the graph completes | `finding_id`, `stop_reason`, `final_decision` (full `TriageDecision` dump), `total_duration_ms`, `per_node_visit_counts`, `per_node_durations_ms`, `per_node_token_totals`, `llm_calls_count`, `tool_calls_count`, `total_tokens`, `confidence_breakdown` (optional), `process_summary` (optional) |

### Graph events

| Type | Emitted | Key fields |
|------|---------|-----------|
| `node_enter` | `on_chain_start` for the four graph nodes (`research`, `analyst`, `critic`, `aggregate`) | `finding_id`, `node`, `visit_index` (per-node counter within finding), `run_id`, `parent_run_id`, `state_snapshot` |
| `node_exit` | `on_chain_end` for the same | `finding_id`, `node`, `visit_index`, `run_id`, `duration_ms`, `state_writes` (the partial dict the node returned to LangGraph) |
| `route_decision` | After each pure routing function | `finding_id`, `from_node`, `to_node`, `predicate`, `state_inputs` |

`state_snapshot` carries the counts a viewer needs without rereading
prior events: `evidence_items_count`, `failed_tool_calls_count`,
`samples_count`, `research_iterations`, `reanalysis_count`,
`last_critique_decision`. For `analyst` and `critic` entries it also
includes `code_bank_summary`, an array of
`{file_path, relevance, content_chars}` describing the bank items the
LLM is about to see (the full content lives on the next `llm_call`).

Stable `predicate` strings on `route_decision`:

- From `analyst`: `samples_non_empty`, `samples_empty`
- From `critic`: `max_research_breaker`, `max_reanalysis_breaker`, `no_critique`, `approved_target_reached`, `approved_more_samples_needed`, `needs_more_research`, `reanalyze`, `unknown`
- From `aggregate`: `verdict_written`, `no_verdict_loopback`

### LLM and tool events

| Type | Emitted | Key fields |
|------|---------|-----------|
| `llm_call` | Paired from `on_chat_model_start` + `on_llm_end` (by `run_id`) | `finding_id`, `node`, `run_id`, `parent_run_id`, `model`, `temperature`, `mode` (`"plain"` / `"with_tools"` / `"structured"`), `structured_schema`, `messages_in` (rich) or `messages_in_hash` + `messages_in_chars` (observability), `response` (rich) or `response_hash` + `response_chars` (observability), `usage_metadata` (`input_tokens`, `output_tokens`, `total_tokens`), `duration_ms` |
| `tool_call` | Paired from `on_tool_start` + `on_tool_end` | `finding_id`, `node`, `run_id`, `parent_run_id` (the requesting `llm_call`), `tool_name`, `args`, `result` (rich) or `result_hash` + `result_chars` + `result_type` (observability), `duration_ms` |
| `error` | Any `*_error` callback | `finding_id`, `node`, `run_id`, `scope` (`"llm"` / `"tool"` / `"chain"` / `"other"`), `error_type`, `error_message`, `retry_attempted` |

`usage_metadata` is taken from `AIMessage.usage_metadata`. It may be
`null` on cached or stubbed responses; aggregated counts in
`finding_complete` and `session_end` exclude unreported usage.

## `finding_complete` v2 fields

`finding_complete` (v2) carries two optional fields that are absent on v1 logs
and on the agent's error path.

**`confidence_breakdown`**: the inputs that produced the calibrated confidence:

| Field | Meaning |
|-------|---------|
| `agreement_rate` | Fraction of surviving samples that agree on `is_vulnerable`; `null` below the corroboration floor (fewer than two samples) |
| `evidence_strength` | Scaled evidence-quality term |
| `agreement_weight` | Configured weight applied to the agreement term |
| `raw_confidence` | Combined confidence before any cap |
| `cap_applied` | Whether the cap was triggered |
| `cap_value` | Cap ceiling in effect |
| `final_confidence` | Equals `final_decision.confidence` |
| `threshold` | Configured decision threshold |
| `sample_votes` | One entry per surviving voting sample (see below) |

Each `sample_votes` entry:

| Field | Meaning |
|-------|---------|
| `is_vulnerable` | This sample's verdict |
| `self_confidence` | Confidence the sample reported for itself |
| `temperature` | Sampling temperature that produced this sample |
| `n_citations` | Number of citation lines in the sample |
| `n_evidence_refs` | Number of evidence references |

`confidence_breakdown` is structural (identical in rich and observability modes).

**`process_summary`**: final per-finding counters:

| Field | Meaning |
|-------|---------|
| `evidence_items_count` | Total evidence items collected |
| `failed_tool_calls_count` | Number of tool calls that errored |
| `reanalysis_count` | Number of reanalysis loops completed |
| `research_stall_streak` | Consecutive research iterations that added no new evidence |

## Correlation model

Three layers of correlation:

1. **`session_id`**: every event in a file shares it. The session is
   the top of the tree.
2. **`finding_id`**: present from `finding_start` through
   `finding_complete`. Filter by this to scope to one finding.
3. **`run_id` / `parent_run_id`**: LangChain's run tree. The viewer
   rebuilds a tree by joining children's `parent_run_id` to ancestor
   `run_id`s:

```
session
 └── finding (finding_start ... finding_complete)
      └── graph (graph_invoke_start ... graph_invoke_end)
           └── node_enter (run_id = N)
                ├── llm_call (parent_run_id = N or deeper)
                │    └── tool_call (parent_run_id = llm_call.run_id)
                └── node_exit (matches the node_enter by run_id)
```

Strict nesting is best-effort: LangChain callback delivery is "best
effort", so a viewer must not assume that `node_exit` always arrives
before sibling events with a later `seq`. Sort by `seq` first, then
group by `run_id`.

## Modes

`--log-mode rich` (default):

- `llm_call.messages_in` is the literal list of LangChain messages
  serialized via `BaseMessage.model_dump()`.
- `llm_call.response` is the raw `LLMResult.model_dump()` including
  `generations[*].message` (the `AIMessage` with `content` and
  `tool_calls`).
- `tool_call.result` is the verbatim tool return value.

`--log-mode observability`:

- `messages_in`, `response`, `result` are absent.
- Their content is replaced by a 16-character SHA-256 prefix
  (`messages_in_hash`, `response_hash`, `result_hash`) and a character
  count (`messages_in_chars`, `response_chars`, `result_chars`).
- Hashes are deterministic for identical input across runs, so a
  viewer can detect repeated prompts without seeing their content.

Token counts, durations and all structural fields are identical across
modes.

## Replay invariant

In `rich` mode, every `llm_call` is sufficient to replay the LLM call
against a stub that returns the recorded `response`. The exact
sequence:

1. Reconstruct each `llm_call.messages_in` into LangChain messages
   (each entry is a `BaseMessage.model_dump()` dict; the `type` field
   tells you which subclass).
2. Feed those messages into a stub LLM whose `ainvoke` returns the
   recorded `llm_call.response`.
3. Run the graph; assert `finding_complete.final_decision` matches the
   recorded one byte-for-byte.

For `with_structured_output` calls, the recorded `messages_in` is the
schema-injected variant the wrapper sent to the model, and `response`
is the raw `AIMessage` with `tool_calls`. The wrapper's post-hoc
Pydantic parsing happens identically on replay.

## Parsing from Python

```python
from pathlib import Path
from pydantic import TypeAdapter
from sast_triage.session_log.events import SessionLogEvent

adapter = TypeAdapter(SessionLogEvent)
events = []
for line in Path("logs/sast_triage_20260528_120000.jsonl").read_text().splitlines():
    if not line.strip():
        continue
    events.append(adapter.validate_json(line))

# Filter to one finding:
finding_id = "8ac6484c12c49772"
finding_events = [
    e for e in events
    if getattr(e, "finding_id", None) == finding_id
]
```

## Worked example

One short SQL-injection finding, six representative events
(truncated). Real logs include many more `llm_call`, `tool_call` and
`node_enter`/`node_exit` events between them.

```jsonl
{"type":"session_start","v":2,"ts":"2026-05-28T12:00:00.000000+00:00","seq":1,"session_id":"abc-123","models":{"research":"gemini-2.5-pro","analyst":"gemini-2.5-pro","critic":"gemini-2.5-pro"},"agent_config":{"INITIAL_SAMPLES":2,"ANALYST_TEMPERATURES":[0.1,0.3,0.5],"CRITIC_TEMPERATURE":0.6},"log_mode":"rich","started_at":"2026-05-28T12:00:00.000000+00:00"}
{"type":"finding_start","v":1,"ts":"2026-05-28T12:00:01.000000+00:00","seq":2,"session_id":"abc-123","finding_id":"8ac6484c12c49772","finding":{"resultHash":"8ac6484c12c49772","queryName":"SQL_Injection","cweID":"89"},"checklist_id":"sqli","checklist_selection_method":"query_name"}
{"type":"node_enter","v":1,"ts":"...","seq":5,"session_id":"abc-123","finding_id":"8ac6484c12c49772","node":"research","visit_index":0,"run_id":"r-1","parent_run_id":"g-1","state_snapshot":{"evidence_items_count":0,"samples_count":0,"research_iterations":0,"reanalysis_count":0,"last_critique_decision":null,"code_bank_summary":null}}
{"type":"llm_call","v":1,"ts":"...","seq":6,"session_id":"abc-123","finding_id":"8ac6484c12c49772","node":"research","run_id":"l-1","parent_run_id":"r-1","model":"gemini-2.5-pro","temperature":0.1,"mode":"with_tools","messages_in":[{"type":"system","content":"..."}],"response":{"generations":[[{"text":"...","message":{"type":"ai","tool_calls":[{"name":"read_file","args":{"file_path":"a.py"}}]}}]]},"usage_metadata":{"input_tokens":820,"output_tokens":35,"total_tokens":855},"duration_ms":1240.5}
{"type":"tool_call","v":1,"ts":"...","seq":7,"session_id":"abc-123","finding_id":"8ac6484c12c49772","node":"research","run_id":"t-1","parent_run_id":"l-1","tool_name":"read_file","args":{"file_path":"a.py"},"result":{"content":"public User findById(String id) { ... }"},"duration_ms":3.1}
{"type":"route_decision","v":1,"ts":"...","seq":42,"session_id":"abc-123","finding_id":"8ac6484c12c49772","from_node":"analyst","to_node":"critic","predicate":"samples_non_empty","state_inputs":{"samples_count":1}}
{"type":"finding_complete","v":2,"ts":"...","seq":98,"session_id":"abc-123","finding_id":"8ac6484c12c49772","stop_reason":"approved","final_decision":{"resultHash":"8ac6484c12c49772","is_vulnerable":true,"confidence":0.85,"suggested_state":"CONFIRMED","justification":"Self-consistency over 2 samples: 100% agreed is_vulnerable=True. ...","agreement_rate":1.0,"sample_count":2},"total_duration_ms":12500.0,"per_node_visit_counts":{"research":1,"analyst":2,"critic":2,"aggregate":1},"per_node_token_totals":{"research":{"input":820,"output":35,"total":855},"analyst":{"input":3200,"output":480,"total":3680}},"llm_calls_count":5,"tool_calls_count":2,"total_tokens":{"input":4020,"output":515,"total":4535},"confidence_breakdown":{"agreement_rate":1.0,"evidence_strength":0.5,"agreement_weight":0.7,"raw_confidence":0.85,"cap_applied":false,"cap_value":0.8,"final_confidence":0.85,"threshold":0.85,"sample_votes":[{"is_vulnerable":true,"self_confidence":0.85,"temperature":0.1,"n_citations":3,"n_evidence_refs":2},{"is_vulnerable":true,"self_confidence":0.79,"temperature":0.3,"n_citations":2,"n_evidence_refs":3}]},"process_summary":{"evidence_items_count":8,"failed_tool_calls_count":0,"reanalysis_count":0,"research_stall_streak":0}}
```

## Versioning

Each event type carries its own `v`. `finding_complete` is at version 2; all
other types remain at version 1. When a type's shape changes, bump only that
type's `v`.
Consumers should default to "I do not understand this event" rather
than crash when they see a version they have not seen before. The
discriminated union enforces the type field but not the per-type
version; a viewer should check `event.v` against the versions it
supports.
