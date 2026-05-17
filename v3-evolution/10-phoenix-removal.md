# 10 — Remove Phoenix tracing

> Scope: rip out Phoenix tracing entirely. Cost was high (extra
> dependencies, optional imports, special CLI paths in two
> commands), value was low (structured per-finding logs are
> sufficient for debugging).
>
> Depends on: nothing.
> Independent of all other v3 work.

## Goal

Simpler codebase. No more `arize-phoenix` /
`openinference-instrumentation-langchain` dependencies. No more
`--trace` CLI flag. The per-finding JSON logs (already structured,
already mature with `--compact-logs`) become the only observability
mechanism.

## Motivation

Phoenix was added in v2 (`v2-evolution/06-phoenix-tracing.md`) to
provide a UI for inspecting LLM traces during development. In
practice:

- The `--trace` flag is rarely used and requires installing optional
  dependencies the user often doesn't have.
- Phoenix server lifecycle (launch, block on Enter, shutdown)
  complicates the CLI exit path.
- The per-finding JSON logs already capture every message, tool
  call, and tool result — same information as a Phoenix trace, in
  a diffable / git-trackable form.
- v3 will produce per-finding logs that are far richer (analyst
  samples, critic decisions, aggregation rationale). Phoenix's
  generic LangChain instrumentation doesn't understand any of this.

If LLM observability ever becomes a real need again (likely on a
team larger than one engineer), the right tool is **Langfuse** (what
sast-ai-workflow uses, supports structured custom traces). Don't
re-add Phoenix; add Langfuse if and when the need is concrete.

## What gets removed

### Files deleted
- `sast_triage/tracing.py` (the whole module, ~108 lines)
- `tests/test_tracing.py`
- `v2-evolution/06-phoenix-tracing.md` (archive to `v2-evolution-archive/` per `11-cleanup-and-docs.md`)

### Files modified

**`run_triage.py`:**
- Remove lines 32-34 (import).
- Remove the `--trace` CLI option from both `run` (line 447-451
  approx) and `interactive` (line 510-514 approx) commands.
- Remove the conditional `if trace or is_tracing_enabled():
  initialize_tracing()` blocks (lines 481-482 and 527-528 approx).
- Remove the shutdown / Press-Enter-to-exit path at the end of
  `interactive` and `run` (if any).

**`requirements.txt`:**
- Drop `arize-phoenix`.
- Drop `openinference-instrumentation-langchain`.
- Drop any related Phoenix sub-deps if present.

**`README.md`:**
- Remove the Phoenix Tracing section.
- Remove `--trace` from the options table.

**`docs/usage-guide.md`:**
- Remove the "Phoenix Tracing" section.
- Remove `--trace` from options table.
- Remove the pip install hint for `arize-phoenix`.

**`docs/architecture.md`:**
- Remove any reference to Phoenix integration.

### Environment variable

`SAST_TRIAGE_TRACE` was used in `tracing.py:is_tracing_enabled`.
Remove. No replacement.

## Implementation steps

1. Delete `sast_triage/tracing.py` and `tests/test_tracing.py`.
2. Remove imports and `--trace` option from `run_triage.py` (both
   `run` and `interactive` commands).
3. Update `requirements.txt` — remove Phoenix-related entries.
4. Update README, usage guide, architecture docs.
5. `pip install -r requirements.txt --upgrade` to verify the new
   environment installs without Phoenix.
6. Run the test suite — `tests/test_tracing.py` is gone, but no
   other test should depend on tracing.
7. Smoke test: `python run_triage.py run <project> --gitleaks-report
   none` runs end-to-end without `--trace`.

## Acceptance criteria

- No file in the repo references `phoenix`, `arize`,
  `openinference`, or `SAST_TRIAGE_TRACE`.
- Test suite passes.
- A fresh install via `pip install -r requirements.txt` does not
  pull `arize-phoenix`.
- README and docs no longer mention Phoenix.

## Risks / rollback

- **Risk:** someone on the team uses `--trace` regularly for
  debugging. **Mitigation:** ask before merging. The per-finding
  JSON logs (especially with `--compact-logs`) are a strict
  superset of what Phoenix shows for our specific use case.
- **Rollback:** single-commit revert.

## Future observability

If/when observability becomes a real need:

- Use **Langfuse** (`langfuse` Python SDK). What sast-ai-workflow
  uses. Supports structured custom traces, not just generic
  LangChain auto-instrumentation. Plugs into `AgentLoggingManager`
  cleanly.
- Set up: ~1 day of work, single integration point.
- **Do not re-add Phoenix.** It's not the right shape for
  multi-LLM-role pipelines.
