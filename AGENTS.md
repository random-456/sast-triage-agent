# AGENTS.md

## Project overview

SAST Triage Agent -- a Python CLI that automates triage of Checkmarx One SAST findings using LangChain and LLMs (Google Vertex AI / Gemini). It fetches findings from the Checkmarx API, clones the repository, preprocesses the codebase to remove sensitive data, and analyzes dataflow paths to make exploitability decisions.

**Tech stack:** Python 3.10+, LangChain 0.3+, Pydantic 2+, Click 8+, pytest, Google Vertex AI, asyncio

## Setup commands

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Build and run commands

```bash
# Activate virtual environment (ALWAYS use it for any Python command)
source .venv/bin/activate

# Run triage (non-interactive)
python run_triage.py run PROJECT_NAME --gitleaks-report <path|none> [OPTIONS]

# Run triage (interactive)
python run_triage.py interactive [-v]

# Run benchmark
python run_benchmark.py --model gemini-2.5-pro --output benchmark_results -v
```

## Testing commands

```bash
# Always use the virtual environment
source .venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_specific.py -v

# Run with coverage
python -m pytest tests/ -v --cov
```

Test configuration lives in `pytest.ini` (asyncio_mode=auto, testpaths=tests).

## Project structure

Tests live next to the code they test in `tests/` subdirectories:

```
sast_triage/          # Core triage logic
    agent_models.py
    tests/
utils/                # Shared helpers (CLI, git, logging, directory)
    tests/
benchmark/            # Benchmark tooling
    tests/
tests/                # Top-level integration tests
    test_data/
config.py             # Application configuration
run_triage.py         # Main CLI entrypoint
run_benchmark.py      # Benchmark runner
```

## Code style

- **PEP8** with 100 character line length
- **Double quotes** for strings
- **Trailing commas** in multi-line structures
- **Type hints** on all function signatures and class attributes
- **Google-style docstrings** for all public functions, classes, and modules
- **Pydantic** for data validation and settings management

### Naming conventions

- Variables/functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private members: `_leading_underscore`
- Enum values: `UPPER_SNAKE_CASE`

### Example showing the expected style

```python
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class TriageResult(BaseModel):
    """Model for a single triage assessment result."""

    result_hash: str
    assessment_result: str = Field(..., pattern="^(CONFIRMED|NOT_EXPLOITABLE)$")
    assessment_confidence: float = Field(..., ge=0.0, le=1.0)
    assessment_justification: str
    created_at: datetime = Field(default_factory=datetime.now)
    is_reviewed: bool = False


def calculate_accuracy(
    predictions: list[str],
    ground_truth: list[str],
) -> float:
    """
    Calculate accuracy of triage predictions against ground truth.

    Args:
        predictions: List of predicted triage results
        ground_truth: List of analyst-provided ground truth results

    Returns:
        Accuracy as a float between 0.0 and 1.0

    Raises:
        ValueError: If lists have different lengths
    """
    if len(predictions) != len(ground_truth):
        raise ValueError("Prediction and ground truth lists must have equal length")

    correct = sum(p == gt for p, gt in zip(predictions, ground_truth))
    return correct / len(predictions)
```

## Testing guidelines

- **TDD approach**: write the test first, watch it fail, write minimal code to pass, refactor
- Use **pytest fixtures** for setup (`conftest.py` for shared fixtures)
- Use descriptive test names: `test_user_can_update_email_when_valid`
- Test edge cases and error conditions
- Aim for 80%+ coverage on critical paths
- Test organization: unit tests (isolated), integration tests (component interactions), e2e tests (full workflows)

## Error handling

- Use **specific exception classes** inheriting from a base exception
- **Fail fast**: check preconditions early and raise immediately
- Use **context managers** for resource management
- Use **structured logging** with `logging.getLogger(__name__)`
- Prefix complex logic comments with `# Reason:`

## Database field naming

- Primary keys: `{entity}_id` (e.g. `user_id`)
- Foreign keys: `{referenced_entity}_id`
- Timestamps: `{action}_at` (e.g. `created_at`, `updated_at`)
- Booleans: `is_{state}` (e.g. `is_active`, `is_verified`)
- Counts: `{entity}_count`
- Durations: `{property}_{unit}` (e.g. `duration_seconds`)

## Git workflow

**Branch strategy:**
- `main` -- production-ready (protected)
- `dev` -- integration branch
- `feature/*` -- new features
- `fix/*` -- bug fixes
- `docs/*`, `refactor/*`, `test/*` -- self-explanatory

**Workflow:**
1. `git checkout dev && git pull origin dev`
2. `git checkout -b feature/your-feature` (or `fix/`, etc.)
3. Make changes + write tests
4. `git push origin feature/your-feature`
5. PR is created manually and merged into `dev`

**Commit message format** (conventional commits):
```
<type>(<scope>): <subject>

<body>

<footer>
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Design principles

- **KISS**: choose straightforward solutions over complex ones
- **YAGNI**: implement features only when needed, not on speculation
- **Single Responsibility**: each function, class, and module has one clear purpose
- **Dependency Inversion**: depend on abstractions, not concrete implementations
- **Open/Closed**: open for extension, closed for modification

## Size limits

- **Files**: max 500 lines of code; split into modules if approaching the limit
- **Functions**: max 50 lines with a single responsibility
- **Classes**: max 100 lines representing a single concept
- **Lines**: max 100 characters

## Boundaries and restrictions

### Never do

- Push directly to `main` -- always branch from `dev`
- Commit secrets, API keys, or `.env` files
- Create files longer than 500 lines
- Add functionality on speculation (YAGNI)
- Mention AI tooling or co-authorship in commit messages

### Never touch

- `.env` files (contain credentials)
- `context/` directory (local test data, gitignored)
- `logs/` directory (runtime output)
- `output/` directory (triage results)
- `.venv/` directory

### Always do

- Use the project's virtual environment for all Python commands
- Write tests for new functionality
- Use type hints on all function signatures
- Use Google-style docstrings on public functions
- Validate with Pydantic where applicable
- Run `python -m pytest tests/ -v` before committing
