# SAST Triage Agent

Automated triage of Checkmarx One SAST findings using LangChain and LLM. Fetches findings from the Checkmarx API, clones the repository, preprocesses the codebase to remove sensitive data, and analyzes dataflow paths to make exploitability decisions.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Checkmarx and GCP credentials
```

**Prerequisites:**
- Python 3.10+
- Access to Google Cloud project with Vertex AI API enabled
- Application Default Credentials configured (`gcloud auth application-default login`)
- Access to a Checkmarx One instance with a valid refresh token
- Git installed

## Usage

### Non-interactive mode

```bash
python run_triage.py run PROJECT_NAME --gitleaks-report <path|none> [OPTIONS]
```

```bash
# Default settings (HIGH + MEDIUM severity, TO_VERIFY state)
python run_triage.py run my-project --gitleaks-report none

# With Gitleaks secret masking, only HIGH severity
python run_triage.py run my-project --gitleaks-report report.csv --severities HIGH

# Filter by state and branch
python run_triage.py run my-project --gitleaks-report none --states TO_VERIFY,CONFIRMED --branch main

# Analyze specific findings by hash
python run_triage.py run my-project --gitleaks-report none --findings abc123,def456
```

### Interactive mode

```bash
python run_triage.py interactive [-v]
```

Guided prompts collect all configuration. A summary is displayed for confirmation before execution.

### Key Options

| Flag | Default | Description |
|------|---------|-------------|
| `--gitleaks-report` | -- | Path to Gitleaks CSV, or `none` (required) |
| `--severities` | `HIGH,MEDIUM` | Comma-separated severity filter |
| `--states` | `TO_VERIFY` | Comma-separated Checkmarx state filter |
| `--branch` | `default.SecurityPipeline` | Git branch to analyze |
| `--findings` | -- | Specific result hashes (bypasses filters) |
| `--model` | `gemini-2.5-pro` | AI model for analysis |
| `--trace` | `false` | Enable Phoenix tracing (localhost:6006) |
| `-v, --verbose` | `false` | Enable debug-level logging |

## Output

Results are saved to a timestamped JSON file in the output directory:

```json
{
  "metadata": {
    "project_name": "my-project",
    "model": "gemini-2.5-pro",
    "summary": { "confirmed": 2, "not_exploitable": 3, "refused": 0 }
  },
  "results": [
    {
      "resultHash": "8ac6484c12c49772",
      "assessment_result": "CONFIRMED",
      "assessment_confidence": 0.92,
      "assessment_justification": "..."
    }
  ]
}
```

Session logs with full conversation history and token usage are saved to `logs/`.

## Testing

```bash
python -m pytest tests/ -v
```

## Benchmark

Compare model accuracy against human-reviewed findings:

```bash
python run_benchmark.py --model gemini-2.5-pro --output benchmark_results -v
```

Benchmark datasets are stored in `benchmark/datasets/`. Each file contains findings with analyst-provided ground truth:

```json
{
  "project": "CXONE PROJECT NAME",
  "github_url": "GITHUB URL",
  "findings": [
    {
      "id": "FINDING ID",
      "language": "JavaScript",
      "category": "SQL_Injection",
      "severity": "HIGH",
      "complexity": "MEDIUM",
      "analyst_triage": {
        "result": "CONFIRMED",
        "justification": "Direct string concatenation in SQL query"
      }
    }
  ]
}
```

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- [Architecture](docs/architecture.md) -- System overview, component descriptions, Mermaid diagrams
- [Usage Guide](docs/usage-guide.md) -- CLI reference for both modes with examples
- [Preprocessing](docs/preprocessing.md) -- Obfuscation and secret masking pipeline
- [Configuration](docs/configuration.md) -- Environment variables, constants, model setup
