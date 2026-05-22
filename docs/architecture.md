# Architecture

## Overview

The SAST Triage Agent automates the triage of Checkmarx One SAST findings using LLM-powered analysis. It fetches findings from the Checkmarx API, clones the associated repository, preprocesses the codebase to remove sensitive data, and then uses a LangChain agent loop to assess each finding for exploitability.

The system is built around a CLI entry point (`run_triage.py`) that orchestrates several components:

| Component | Location | Responsibility |
|-----------|----------|---------------|
| CLI | `run_triage.py` | Entry point, argument parsing, orchestration |
| Agent | `sast_triage/agent.py` | LLM interaction loop, tool dispatch, decision collection |
| Tools | `sast_triage/agent_tools.py` | File reading, code search, decision submission |
| Prompts | `sast_triage/prompts.py` | System and input prompt templates |
| Models | `sast_triage/agent_models.py` | Pydantic models for triage decisions |
| Preprocessing | `sast_triage/preprocessing/` | Obfuscation and secret masking |
| Interactive | `sast_triage/interactive.py` | Guided prompt collection for interactive mode |
| Logging | `sast_triage/agent_logging.py` | Session logging with token tracking |
| Checkmarx | `utils/checkmarx_helpers.py` | API client for fetching findings |
| Git | `utils/git_helpers.py` | Repository cloning |
| Findings | `utils/findings_helpers.py` | CSV/JSON persistence of findings data |
| Directories | `utils/directory_helpers.py` | Temp and output directory management |

## Processing Flow

```mermaid
flowchart LR
    A[CLI Input] --> B{Mode?}
    B -->|run| C[Parse CLI Args] --> E
    B -->|interactive| D[Guided Prompts] --> D1{Confirm Config?}
    D1 -->|No| X[Exit]
    D1 -->|Yes| E[Resolve Project & Fetch Findings]
    E --> F[Clone & Preprocess Codebase]
    F --> G{Interactive?}
    G -->|No| I[Run Triage Analysis]
    G -->|Yes| H{Confirm Preprocessing?}
    H -->|No| X
    H -->|Yes| I
    I --> J[Save Results + Logs]
```

### Step-by-step

1. **CLI Input** -- The user invokes either `run` (non-interactive) or `interactive` mode via Click sub-commands.
2. **Project Resolution** -- The Checkmarx API client authenticates, looks up the project by name, and retrieves the project ID and repository URL.
3. **Findings Fetch** -- Findings are retrieved from the Checkmarx `/api/results` endpoint, filtered by severity. A client-side state filter is applied afterward.
4. **Repository Clone** -- The repository is shallow-cloned (`--depth 1`) into a temporary directory.
5. **Preprocessing** -- The cloned codebase is processed in two stages: obfuscation removes infrastructure patterns (IPs, MACs, FQDNs), and secret masking replaces secrets identified by a Gitleaks CSV report.
6. **Analysis** -- Each finding is processed through the LLM agent loop (see below).
7. **Output** -- Results are saved incrementally to a timestamped JSON file with metadata.

## Agent Analysis Loop

```mermaid
flowchart TD
    A[Load Finding Details] --> B[Send to LLM with System Prompt]
    B --> C{LLM Response}
    C -->|Tool Call| D[Execute Tool]
    D --> E[Add Result to Conversation]
    E --> B
    C -->|submit_triage_decision| F[Record Decision]
    C -->|No Tool Call| G[Prompt: Use a Tool]
    G --> B
    F --> H[Save Result + Update CSV]
```

The agent uses a tool-calling pattern with LangChain:

1. The finding details (dataflow, severity, query name, CWE) are formatted into a human prompt and sent to the LLM alongside a system prompt. The system prompt enforces a mandatory five-step analysis protocol (identify source, identify sink, enumerate the path, classify every guard, verdict), with a `file:line` citation required for each claim. A CWE-specific evidence checklist is appended to the system prompt, selected from the finding's `queryName` and `cweID` (see CWE Checklists below); findings with no matching checklist receive a generic fallback.
2. The LLM responds with tool calls to investigate the codebase: `read_file`, `search_in_files`, `list_directory`.
3. A `verify_analysis` checkpoint tool ensures the agent reviews its reasoning before submitting.
4. The final `submit_triage_decision` tool records the classification (`is_vulnerable`) with confidence and justification. The advisory `suggested_state` is then derived from those two fields (see Output Model below).
5. If the LLM responds without a tool call, a nudge message is injected to keep the loop progressing.
6. The loop is capped at a configurable maximum number of iterations (default: 30).

### Available Tools

| Tool | Purpose |
|------|---------|
| `read_file` | Read a file from the cloned codebase (path-traversal protected) |
| `search_in_files` | Regex search across codebase files with extension filtering |
| `list_directory` | List directory contents within the codebase |
| `verify_analysis` | Verification checkpoint before final decision |
| `submit_triage_decision` | Submit the final exploitability verdict |

### CWE Checklists

Each finding's analyst prompt is augmented with a CWE-specific evidence checklist. Checklists live in `sast_triage/checklists/` as YAML files validated against the `ChecklistDocument` model. `_mapping.yaml` routes a finding to a checklist: first by an exact, case-insensitive `queryName` match, then by the normalized CWE (`CWE-<n>`), then to `generic.yaml` as the final fallback. A checklist supplies the required evidence, the controls that do and do not neutralize that vulnerability class, investigation guidance and common false-positive patterns. Selection is fail-safe: a missing or malformed checklist leaves the base prompt unchanged rather than blocking the run.

## Preprocessing Pipeline

```mermaid
flowchart LR
    A[Cloned Repo] --> B[Obfuscation]
    B --> C[Secret Masking]
    C --> D[Ready for Analysis]
    B -->|Report| E[Session Log]
    C -->|Report| E
```

The preprocessing pipeline runs after repository cloning and before LLM analysis. Both stages produce structured reports that are recorded in the session log. See [preprocessing.md](preprocessing.md) for details.

## Output Model

Each finding's output separates two concerns:

- **Classification** (`is_vulnerable`: `true` | `false` | `null`, plus a `confidence` in 0.0-1.0): what the agent believes about exploitability.
- **Disposition** (`suggested_state`): what to do about it, derived deterministically from the classification and confidence by `derive_state` in `sast_triage/agent_models.py`.

The derivation: a positive (`is_vulnerable=true`) is always `CONFIRMED` regardless of confidence, since missing a real vulnerability is the worst outcome. A negative at or above `CONFIDENCE_THRESHOLD` is `NOT_EXPLOITABLE`; below it, `PROPOSED_NOT_EXPLOITABLE` (flagged for human review). An undecided classification (`null`) is `REFUSED`.

Keeping classification and disposition separate means tuning `CONFIDENCE_THRESHOLD` shifts findings between `NOT_EXPLOITABLE` and `PROPOSED_NOT_EXPLOITABLE` without changing the classification metrics the benchmark gates on.

**Read-only constraint:** the tool only reads from Checkmarx One. Every `suggested_state` is advisory and is stored only in the local output file. No triage state is ever written back to Checkmarx.

## LLM Backend

The agent uses Google Gemini through the unified `ChatGoogleGenerativeAI` client from `langchain-google-genai`. The same client talks to either backend, selected by environment variable:

- **Vertex AI** (production): `GOOGLE_GENAI_USE_VERTEXAI=true` with `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`. Auth via Application Default Credentials.
- **Google AI Studio** (local development): `GOOGLE_API_KEY`, prepaid and budget-cappable.

The model is controlled by the `--model` CLI flag or the interactive prompt. Backend resolution happens once at startup in `config.resolve_genai_backend`.

## Session Logging

Every triage session produces a timestamped JSON log file in the `logs/` directory containing:

- **Session metadata**: model, temperature, project details, branch, repository URL
- **Preprocessing reports**: obfuscation and masking summaries
- **Per-finding conversation**: full message history, tool calls and results, token usage
- **Session summary**: totals for confirmed/not_exploitable/refused, aggregate token usage

## Output Structure

```
<output-dir>/
    findings_assessment_<project>_<timestamp>.json   # Triage decisions with metadata
```

The findings assessment file contains a metadata wrapper with project context and summary statistics, plus the full list of per-finding results. Results are saved incrementally after each finding is processed.

The temporary directory (`temp/`) holds intermediate data during execution:

```
temp/
    codebase/       # Cloned and preprocessed repository
    findings/
        triage_list.csv           # Finding IDs with severity, state, triage status
        findings_details.json     # Detailed finding data with dataflow
```
