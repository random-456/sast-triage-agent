# 03 — LLM backend: migrate to `langchain-google-genai`

> Scope: replace `langchain-google-vertexai.ChatVertexAI` with
> `langchain-google-genai.ChatGoogleGenerativeAI`, which is the
> unified entrypoint to both Vertex AI (production) and Google AI
> Studio (local development with prepaid budget caps).
>
> Depends on: `02-gold-set-benchmark.md` (so we can verify
> migration doesn't regress accuracy).

## Goal

One LLM client class. One env-var flip switches between Vertex
(corporate machine, production) and AI Studio (local dev,
prepaid). No factory abstraction needed.

## Background

`langchain-google-vertexai` is now deprecated (as of
langchain-google-genai 4.0, September 2025). The unified
`ChatGoogleGenerativeAI` class in `langchain-google-genai` talks to
both backends via the underlying `google-genai` SDK. Per-token
pricing is identical on the paid tiers of both backends.

The corporate machine keeps working — the new library still supports
Vertex AI fully, just via a unified code path. This is a one-line
config switch via env var, not a re-architecture.

## What changes

### 1. `requirements.txt`

Remove:
```
langchain-google-vertexai
```

Add:
```
langchain-google-genai>=4.0
google-genai
```

Note: `langchain-google-vertexai` had a sub-import for
`ChatAnthropicVertex` (Claude on Vertex Model Garden). If Claude
support is still needed, keep `langchain-google-vertexai` installed
*alongside* the new library and import only `ChatAnthropicVertex`
from it. (Most likely scenario: drop Claude support — v3 is built
specifically for Gemini 2.5 Pro.)

### 2. `sast_triage/agent.py`

Replace lines 12-13 and 86-107 with a single unified initializer:

```python
from langchain_google_genai import ChatGoogleGenerativeAI

# In __init__:
self.llm = ChatGoogleGenerativeAI(
    model=model_name,
    temperature=temperature,
    max_retries=3,
)
```

Auth and backend selection are handled via env vars at process startup
(see `config.py` change below), so the agent class itself doesn't
need to know which backend it's talking to.

If Claude support is being kept, branch on `model_name` as today
but use `langchain-google-genai` for everything Gemini.

### 3. `config.py`

Add backend-selection logic at module top:

```python
import os

# Vertex AI (production) vs AI Studio (local dev) is selected by env var.
# Production / corporate machine: set GOOGLE_GENAI_USE_VERTEXAI=true
# and GOOGLE_CLOUD_PROJECT=<project>.
# Local dev: set GOOGLE_API_KEY=<AI Studio key> only.
if os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("true", "1"):
    # Vertex AI; relies on Application Default Credentials.
    GOOGLE_CLOUD_PROJECT = os.environ["GOOGLE_CLOUD_PROJECT"]
elif not os.getenv("GOOGLE_API_KEY"):
    raise RuntimeError(
        "Neither GOOGLE_API_KEY (AI Studio) nor "
        "GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT (Vertex) is set."
    )
```

### 4. `benchmark/justification_check/__init__.py`

Lines 4 and 30 reference `ChatVertexAI`. Replace with
`ChatGoogleGenerativeAI` in the same way.

### 5. Tests

`tests/test_agent_logging.py:183,210` and `tests/test_agent.py:29`
patch `sast_triage.agent.ChatVertexAI`. Update to patch
`sast_triage.agent.ChatGoogleGenerativeAI`.

### 6. `.env.example`

Update to show both modes:

```bash
# --- Production (Vertex AI) ---
# GOOGLE_GENAI_USE_VERTEXAI=true
# GOOGLE_CLOUD_PROJECT=my-vertex-project
# (Auth via `gcloud auth application-default login`)

# --- Local development (Google AI Studio) ---
# GOOGLE_API_KEY=AIza...
# (Prepaid, budget-cappable; same per-token price as Vertex paid tier)
```

### 7. Documentation

- `README.md` — update Prerequisites section. AI Studio is now a
  supported alternative to Vertex AI for local development.
- `docs/configuration.md` — update env var table to reflect
  `GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_CLOUD_PROJECT`,
  `GOOGLE_API_KEY`. Drop references to `PROJECT_ID`,
  `DEFAULT_LOCATION` (Vertex-specific naming).

## De-risk strategy

This is the highest-risk Phase 1 change because it touches the LLM
client itself. Mitigations:

1. **Before/after gold-set comparison.** Run the v2 gold-set
   benchmark (committed at end of Phase 0) before the migration,
   then again after. **Same baseline numbers required, ±2 F1 points
   tolerance.** If results differ more than that, investigate before
   merging — likely a tool-calling shape mismatch.
2. **Single isolated commit.** No other changes in the same commit.
   Easy revert.
3. **Keep legacy library installed for one release.** `requirements.txt`
   keeps `langchain-google-vertexai` until v3.1, in case
   `ChatAnthropicVertex` is needed.
4. **Smoke test tool calls.** Verify the existing
   `read_file`/`search_in_files`/`list_directory` tools work with
   the new client on at least 5 findings before running the full
   benchmark.

## Acceptance criteria

- Single isolated commit, ~10 file changes (`agent.py`, `config.py`,
  `requirements.txt`, two test files, `benchmark/justification_check`,
  `.env.example`, `README.md`, `docs/configuration.md`).
- All tests pass.
- Gold-set benchmark numbers match within ±2 F1 points.
- Local dev on AI Studio works (verified manually by running 5
  findings via `GOOGLE_API_KEY`).
- Corporate Vertex AI path still works (verified by user on the
  target machine).

## Risks / rollback

- **Risk:** Gemini 2.5 Pro tool-calling has small behavior
  differences on the new SDK that cause regressions. **Probability:**
  medium. **Mitigation:** the gold-set before/after comparison
  catches this. If it triggers, the safest path is to defer
  migration — the architecture redesign doesn't *require* AI Studio
  support, it just makes local dev cheaper.
- **Rollback:** single-commit revert. `requirements.txt` keeps
  legacy library in place for this reason.

## Out of scope

- Multi-provider abstraction (OpenAI, Anthropic, etc.). v3 targets
  Gemini 2.5 Pro exclusively. If/when the org gets access to other
  models, that's a future redesign.
