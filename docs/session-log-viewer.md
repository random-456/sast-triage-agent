# Session Log Viewer

A local, browser-based viewer for the JSONL session logs that the triage
agent writes to `logs/`. The viewer is a single static page; it has no
server, no build step and no network access. It exists to support
benchmarking and iteration on the agent: load a session log, browse the
per-finding flow, drill into LLM prompts/responses and tool calls,
compare two runs.

The viewer is bundled with the repository under `viewer/` and is treated
as a tool rather than a shipped feature. It is expected to evolve as the
agent does.

## Opening it

Open `viewer/index.html` in a browser (double-click or `File > Open`).
Tested on recent Chromium-based browsers and Firefox. No installation,
no dependencies.

Load a session log with the **Browse...** button or by dropping one or
more `.jsonl` files onto the drop-zone. Loaded sessions appear in the
sidebar. Click one to open it in a new in-app tab.

For parallel viewing of independent sessions, open the viewer again in a
separate browser tab. Each browser tab is an isolated instance with its
own state.

## Panes

Selecting a session in the sidebar opens a session tab with the
following layout.

```
┌─────────────────────────────────────────────────────┐
│  Session summary  ·  Search                         │
├─────────────────────────────────────────────────────┤
│  Findings table (sortable)                          │
├─────────────────────────────────────────────────────┤
│  Finding header (full-width, when a row is selected)│
├─────────────────────────────────────────────────────┤
│  Topology  +  Traversal flow                        │
├──────────────────────────────┬──────────────────────┤
│                              │                      │
│  Timeline                    │  Inspector           │
│  (one row per event)         │  (selected event)    │
│                              │                      │
└──────────────────────────────┴──────────────────────┘
```

**Findings table.** One row per finding. Sortable by any column: result
hash, suggested state, confidence, sample count, research iterations,
reanalysis loops, total tokens, duration, stop reason. The `samples`
column shows the voted sample count (`final_decision.sample_count`) and the
`reanalysis` column shows the reanalysis-loop count
(`process_summary.reanalysis_count`). The analyst-call count is surfaced in
the finding header as the "attempts" figure. Click a row to load its header,
topology, traversal and timeline.

**Finding header.** When a finding row is selected, a full-width header card
appears below the findings table and above the topology. It shows a verdict
line (suggested state, confidence, CWE, checklist and its selection method,
stop reason, the voted sample count and reanalysis-loop count, duration,
tokens) and three collapsible blocks:

- Confidence breakdown: the agreement and evidence terms, the weight, the raw
  and capped values, the threshold and the resulting disposition.
- Per-sample vote table: one row per surviving sample with its verdict,
  self-reported confidence, sampling temperature, citation count and evidence
  reference count.
- Process diagnostics: research counters, the critic decision trail and a cost
  line.

The header is populated from the `confidence_breakdown` and `process_summary`
fields on `finding_complete` (v2). For v1 logs or findings that ended on the
error path the collapsible blocks are absent.

**Topology.** A static reference diagram of the per-finding graph
(`research → analyst → critic → aggregate`) with a visit count and
total duration per node. Visited nodes are highlighted.

**Traversal.** The actual sequence of node visits for the selected
finding, derived from `node_enter` events in order. Useful for spotting
loops (research run multiple times, critic bouncing back).

**Timeline.** One line per event, ordered by sequence number. Each row
shows timestamp, event type and a compact summary. Click a row to load
its full content into the inspector. The search box filters the
timeline by free-text substring across the event content.

**Inspector.** Renders the full content of the selected event:
- For `llm_call`: metadata (model, mode, temperature, tokens, duration),
  then each input message as a collapsible block, then the parsed
  structured-output result (when applicable) and the raw `LLMResult` as
  a collapsible JSON block.
- For `tool_call`: arguments, result.
- For `node_enter`: state snapshot and, when present, the code-bank
  summary (file paths and sizes, not contents).
- For `finding_complete`: verdict, justification, per-node visit counts,
  durations and token totals. On v2 events, also renders the confidence
  breakdown and per-sample votes.
- Long content (over ~4 KB) is truncated inline with a "Show all"
  button that opens it in a modal.

## Compare view

When two or more sessions are loaded, a **Compare** button appears at
the bottom of the sidebar. The compare tab pairs findings by
`resultHash` across two sessions and shows per-finding deltas:
suggested-state change, confidence delta, token delta, duration delta.
Useful when iterating on the agent or comparing model versions.

## Security model

The viewer runs entirely client-side from a local file. It does not
make network requests and does not store data. A few details:

- All rendering is via `textContent` and DOM element creation. No
  `innerHTML`, no string-template HTML, no `eval`, no dynamic script
  construction.
- `index.html` ships a strict Content Security Policy in a `<meta>` tag:
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'none'; font-src 'none'; object-src 'none'`.
  No remote anything; no inline scripts; no images.
- File access is via `<input type="file">` and drag-drop only.
- Session logs may contain LLM responses and tool results derived from
  attacker-influenceable inputs (a malicious finding). The CSP and
  textContent-only rendering are the defense.

The viewer is intended for local exploration of logs from the project's
own runs. It is not intended to be deployed or served.

## Coupling to the triage agent

The viewer reads the event schema defined in
[`docs/session-log.md`](session-log.md) and the topology defined in
`sast_triage/graph/build.py`. Changes to either may require viewer
updates:

- **New event type** in `sast_triage/session_log/events.py`: the
  timeline summary and inspector for it need handlers in `viewer.js`
  (`renderEventSummary`, `inspectorBody`). Without them, the row still
  renders but with no summary or inspector body.
- **New graph node** in `sast_triage/graph/build.py`: add the node name
  to `NODE_NAMES` at the top of `viewer.js` so visit counts and
  topology rendering pick it up.
- **Renamed routing predicate** in
  `sast_triage/session_log/routing_hooks.py`: no viewer change needed;
  the viewer renders whatever predicate string the event carries.
- **Renamed CLI flag** for log mode: no viewer change needed; the
  viewer renders the `log_mode` value from `session_start` verbatim.
- **`finding_complete` schema changes**: the finding header and inspector
  read `confidence_breakdown` and `process_summary` (both added in v2).
  Schema changes to those shapes require corresponding updates in
  `viewer.js` (`renderFindingHeader`, `inspectorBody`).

If the agent architecture changes substantially (for example, a new
node type or a new aggregation step), update `viewer/viewer.js` in the
same change. Treat the viewer as in-scope for any work that affects the
graph topology or the event schema.

## Files

```
viewer/
  index.html      shell and CSP
  viewer.css      styling
  viewer.js       parser, UI, search, compare
  README.md       one-line pointer to this doc
```

No build step. Plain `<script src="viewer.js">` and
`<link rel="stylesheet" href="viewer.css">`.

## Known limitations

- Reloading the browser tab clears all loaded sessions and inspector
  state. Persistence is not implemented.
- Cross-session global search is not implemented; search is per-tab.
- Calibration curves and aggregate benchmark plots are not implemented;
  use `python run_benchmark.py` for those.
