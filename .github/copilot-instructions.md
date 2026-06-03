# Copilot instructions

Guidance for GitHub Copilot working in this repository: a Python CLI that triages Checkmarx SAST findings for exploitability (LangChain + Google GenAI / Gemini via Vertex AI or AI Studio, Pydantic, pytest, asyncio).

These are directives, not suggestions.

## Build, test and run

- Always use the project virtualenv: run `source .venv/bin/activate` before any Python command.
- Run the tests with `python -m pytest`. Setup, run and benchmark commands are in `README.md`.
- Async tests rely on `asyncio_mode = auto` (in `pytest.ini`); do not decorate them manually.

## Project layout

```
sast_triage/        core triage logic and agent models
    checklists/     per-CWE evidence checklists (YAML) + selection logic
    graph/          per-finding LangGraph nodes (research, analyst, critic, aggregate) + routing
    session_log/    JSONL session logger
    tests/
utils/              shared helpers (utils/tests/)
benchmark/          benchmark tooling (benchmark/tests/)
tests/              top-level integration tests
docs/               architecture, usage, configuration, benchmark, session-log notes
viewer/             static browser-based session-log viewer
config.py           configuration constants
run_triage.py       main CLI entrypoint
run_benchmark.py    benchmark runner
```

Tests live in a `tests/` subdirectory of each package; top-level integration tests live in `tests/`.

Do not touch (local or gitignored runtime data): `.env`, `.venv/`, `context/`, `logs/`, `output/`.

## Core principles

- KISS: choose the straightforward solution. Justify any abstraction, pattern or config knob with a concrete present need.
- YAGNI: build only what the task requires. No speculative features or hooks for later.
- SOLID, applied lightly: one purpose per function, class and module; extend via new code rather than rewriting stable code; depend on abstractions for LLM clients, API clients and IO.
- Fail fast: validate at boundaries and raise early. No silent fallbacks that mask real errors.

## Code style

- PEP 8 with 100-char lines. Double quotes for strings; trailing commas in multi-line structures.
- Type hints on all function signatures and class attributes. Pydantic for data validation and settings.
- Google-style docstrings on public functions, classes and modules; skip when the signature is self-explanatory.
- Size limits: file 500 lines, function 50 lines (one job), class 100 lines (one concept).
- Naming: `snake_case` for variables and functions, `PascalCase` for classes, `UPPER_SNAKE_CASE` for constants and enum values, `_leading_underscore` for private members, `snake_case.py` for files.
- Comments explain the *why* only (constraints, workarounds, surprising behavior); prefix a non-obvious choice with `# Reason:`. Do not narrate what the code does.

## Writing style (every text you generate: code comments, commit messages, docs, output)

- No Oxford commas: write "red, green and blue", not "red, green, and blue".
- No em-dashes or en-dashes as sentence punctuation. Use a colon, a period, a semicolon, parentheses or rephrase. Hyphens in compound words are fine.
- Plain prose. No marketing voice, no filler adjectives.
- Do not mention AI assistants, Copilot or co-authorship anywhere: not in commit messages, pull requests, code, comments or docs.

## Testing

- Test-first for a bug fix or new behavior: write the failing test, then the code.
- Use pytest fixtures for setup (`conftest.py` for shared fixtures).
- Descriptive names: `test_<unit>_<condition>_<expected>`. Cover edge cases and error conditions, not just the happy path.
- No non-trivial logic is complete without tests.

## Error handling and logging

- Raise specific exception classes so callers can discriminate; do not raise bare strings or a generic `Exception` for domain failures. Catch only what you can handle and re-raise unknowns after logging. Use context managers for files, network clients and temp dirs.
- Structured logging via `logger = logging.getLogger(__name__)`. No `print` in committed code outside CLI entry points. Pass context via `extra=`, not by interpolating into the message. Never log secrets, tokens or full request/response bodies.

## Configuration and security

- Validate required env vars at startup (Pydantic Settings); fail loudly on missing or invalid values; never silently default in production. Document keys in `.env.example`; never commit `.env`.
- Never commit secrets or API keys. Validate and sanitize all external input (Checkmarx API responses, cloned repo paths, gitleaks CSVs, user-supplied flags).
- Keep tokens out of logs and out of `.git/config` or remote URLs. Use HTTPS for all external calls.

## Git workflow

- Never commit to `main` directly. Branch from `dev`: `git checkout -b <type>/<short-description>`, where type is feature, fix, docs, refactor, test or chore.
- Open pull requests against `dev`, never `main`. Do not enable auto-merge and do not merge the pull request yourself.
- Commit message format: `<type>(<scope>): <subject>`, where type is feat, fix, docs, style, refactor, test or chore. Keep the subject imperative and concise.
- Never assume or guess: when a path, name or API is unclear, read the file or grep before acting. Check `requirements.txt` before adding a dependency.

## Reference docs

`docs/architecture.md` (system design and data flow), `docs/usage-guide.md`, `docs/configuration.md`, `docs/benchmark.md`, `docs/checklists.md`, `docs/session-log.md`, `docs/session-log-viewer.md`, `docs/decisions.md` (recorded design decisions).
