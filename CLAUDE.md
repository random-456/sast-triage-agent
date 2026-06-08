# CLAUDE.md

Guidance for Claude Code when working in this repository (Python CLI: LangChain + Google GenAI / Gemini via Vertex AI or AI Studio, Pydantic, pytest, asyncio).

These are directives, not suggestions. Apply them; don't just read them.

Setup, run and test commands live in `README.md`. Always run Python commands inside the project's `.venv` (`source .venv/bin/activate`).

---

## Core principles

- **KISS**: choose the straightforward solution. Complexity needs explicit justification: if you reach for an abstraction, a pattern or a config knob, you must be able to point to a concrete reason it's needed *now*.
- **YAGNI**: build only what the current task requires. No speculative features, no hooks "in case we need it later", no premature configurability.
- **SOLID, applied lightly**:
  - Single Responsibility: one purpose per function/class/module.
  - Open/Closed: extend via new code; don't rewrite stable code to add a variant.
  - Dependency Inversion: depend on abstractions, not concretions (especially for LLM clients, API clients, IO).
- **Fail fast**: validate at boundaries, raise early. No silent fallbacks that mask real errors.

---

## Writing style (for any text you generate)

Applies to commit messages, code comments, docs, CLI output and responses to the user.

- **No Oxford commas.** Write "red, green and blue", not "red, green, and blue".
- **No em-dashes (—) or en-dashes (–) as sentence punctuation.** Use a colon, a period (new sentence), a semicolon, parentheses or rephrase. Hyphens in compound words are fine.
- Plain prose. No marketing voice, no filler adjectives.
- **Never mention AI assistants, Claude, Copilot or co-authorship anywhere:** not in commit messages, pull requests, code, comments or docs.

---

## Code structure & limits

- File: max 500 lines. If approaching, split by responsibility.
- Function: max 50 lines, one clear job.
- Class: max 100 lines, one concept.
- Line length: 100 chars.
- Tests live next to the code they test in a `tests/` subdirectory of each package (`sast_triage/tests/`, `utils/tests/`, `benchmark/tests/`). Top-level integration tests live in `tests/`.

---

## Style

- **PEP 8** with 100-char lines.
- Double quotes for strings, trailing commas in multi-line structures.
- Type hints on all function signatures and class attributes.
- **Pydantic** for data validation and settings management.
- Google-style docstrings on public functions, classes and modules. Skip when the signature is self-explanatory.

### Naming

- Variables, functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private members: `_leading_underscore`
- Enum values: `UPPER_SNAKE_CASE`
- Files: `snake_case.py`

---

## Documentation in code

- Module header docstring when the file's purpose isn't obvious from its name.
- Docstrings on public functions: what it does, args, raises, non-obvious return semantics. Skip when the signature is self-explanatory.
- Inline comments only for the *why*: hidden constraints, workarounds, surprising behavior. Prefix with `# Reason:` when explaining a non-obvious choice.
- Don't narrate what the code does. Well-named identifiers do that.

---

## Testing

- Test-first when fixing a bug or building a new behavior: write the failing test, then the code.
- Use **pytest fixtures** for setup (`conftest.py` for shared fixtures).
- Descriptive test names: `test_<unit>_<condition>_<expected>`.
- Cover edge cases and error conditions, not just the happy path.
- Aim for meaningful coverage on critical paths over a coverage percentage.
- Async tests rely on `asyncio_mode = auto` in `pytest.ini`; don't decorate manually.

---

## Error handling

- Specific exception classes (`class FooError(Exception)`) so callers can discriminate. Don't raise bare strings or generic `Exception` for domain failures.
- Catch only what you can handle. Re-raise unknowns after logging.
- Use context managers for resource management (files, network clients, temp dirs).
- Don't wrap code that can't realistically fail; it hides bugs.

---

## Logging

- Structured logging via `logger = logging.getLogger(__name__)`. No `print` in committed code outside CLI entry points.
- Pass context via the `extra=` kwarg or structured fields, not by interpolating into the message string.
- Levels: `error` (something broke), `warning` (off but recoverable), `info` (notable events), `debug` (development only).
- Never log secrets, tokens or full request/response bodies that may contain them.

---

## Configuration

- All required env vars validated at startup via Pydantic Settings. Fail loudly on missing or invalid values; never silently default in production.
- Document required keys in `.env.example`. Never commit `.env`.
- Current keys: `BASE_URL`, `REFRESH_TOKEN` (Checkmarx One); for the Google GenAI backend either `GOOGLE_GENAI_USE_VERTEXAI=true` + `GOOGLE_CLOUD_PROJECT` (plus optional `GOOGLE_CLOUD_LOCATION`) for Vertex AI, or `GOOGLE_API_KEY` for AI Studio; optional `GITHUB_TOKENS` (per-host clone auth). Backend selection is resolved by `config.resolve_genai_backend()`.

---

## Security

- Never commit secrets, API keys or `.env` files.
- Validate and sanitize all external input: Checkmarx API responses, cloned repo paths, gitleaks CSVs, user-supplied flags.
- Keep tokens out of logs and out of `.git/config` or remote URLs. The existing `GITHUB_TOKENS` flow sends tokens via the HTTP Basic header only; preserve that.
- HTTPS for all external calls.
- Run `pip-audit` (or equivalent) periodically; address high/critical findings.

---

## Performance

Profile before optimizing. Don't micro-optimize speculatively. When something is actually slow: measure, fix the hot path, re-measure.

---

## Git workflow

**The `main` branch MUST never be touched directly. Always branch from `dev`.**

1. `git checkout dev && git pull origin dev`
2. `git checkout -b <type>/<short-description>`. Types: `feature`, `fix`, `docs`, `refactor`, `test`, `chore`.
3. Make changes and tests.
4. `git push origin <branch>`.
5. Open the PR with `gh pr create` after showing the user the proposed title and body for confirmation. Target `dev`, never `main`. Never enable auto-merge. Never merge the PR; the user does that.
6. Immediately after `gh pr create` returns the URL, open it in the user's browser so they can review and merge without context-switching.

### Commit messages

Format: `<type>(<scope>): <subject>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(triage): add per-finding confidence threshold

- Threshold applied after assessment, before write-back
- New `--min-confidence` CLI flag, defaults to 0.0

Closes #42
```

**Never mention Claude, AI or co-authorship in commit messages.**

---

## Important rules of engagement

- **Never assume or guess.** When a path, name or API isn't clear, verify (grep, read the file) before acting.
- **Check `requirements.txt` before adding a dependency.** The project may already have an equivalent.
- **Keep this file accurate** when adding new conventions, paths or stack changes.
- **No feature is complete without tests** for any non-trivial logic.

---

## SAST-triage-specific

### Project structure

```
sast_triage/          # Core triage logic and agent models
    checklists/       # Per-CWE evidence checklists (YAML) + selection logic
    graph/            # Per-finding LangGraph nodes (research, analyst, critic, aggregate) + routing
    preprocessing/    # Code obfuscation and secret masking
    session_log/      # JSONL session logger (events, writer, callback)
    tests/
utils/                # Shared helpers (CLI, git, logging, directory)
    tests/
benchmark/            # Benchmark tooling
    tests/
tests/                # Top-level integration tests
    test_data/
docs/                 # Architecture, usage, benchmark notes
viewer/               # Local browser-based session-log viewer (static)
config.py             # Pydantic settings
run_triage.py         # Main CLI entrypoint
run_benchmark.py      # Benchmark runner
```

### Never touch

- `.env` (credentials)
- `.venv/` (virtualenv)
- `context/` (local test data, gitignored)
- `logs/` (runtime output, gitignored)
- `output/` (triage results, gitignored)

### Important docs

- `docs/architecture.md`: system design and data flow
- `docs/usage-guide.md`: CLI usage and flags
- `docs/configuration.md`: env vars and runtime config
- `docs/checklists.md`: per-CWE evidence checklists and selection logic
- `docs/preprocessing.md`: code preprocessing and obfuscation
- `docs/benchmark.md`: benchmark harness
- `docs/decisions.md`: recorded design decisions
- `docs/session-log.md`: JSONL event schema reference
- `docs/session-log-viewer.md`: local browser viewer under `viewer/` (read this when changing topology or event schema)
