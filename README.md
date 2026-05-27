# SAST Triage Agent

Automated triage of Checkmarx One SAST findings. Fetches findings from the Checkmarx API, clones the repository, preprocesses the codebase to remove sensitive data and runs each finding through a per-finding research, analyst and critic graph that produces a structured exploitability verdict with a calibrated confidence.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Checkmarx credentials and the Google GenAI backend settings.
```

**Prerequisites:**
- Python 3.10+
- A Google Cloud project with the Vertex AI API enabled and Application Default Credentials (`gcloud auth application-default login`)
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
| `--compact-logs` | `false` | Reduced agent log (no input prompt bodies, system prompt by hash, tool result bulk arrays dropped). Dev analysis only. |
| `-v, --verbose` | `false` | Enable debug-level logging |

## Output

Results are saved to a timestamped JSON file in the output directory:

```json
{
  "metadata": {
    "project_name": "my-project",
    "model": "gemini-2.5-pro",
    "summary": {
      "confirmed": 2,
      "not_exploitable": 2,
      "proposed_not_exploitable": 1,
      "refused": 0,
      "refusal_rate": 0.0
    }
  },
  "results": [
    {
      "resultHash": "8ac6484c12c49772",
      "is_vulnerable": true,
      "confidence": 0.92,
      "suggested_state": "CONFIRMED",
      "justification": "..."
    }
  ]
}
```

Each result separates the classification (`is_vulnerable` and `confidence`) from the advisory `suggested_state`. The tool only reads from Checkmarx One; verdicts are written to the local output file and are never written back to Checkmarx. See [docs/usage-guide.md](docs/usage-guide.md#output) for the full state derivation.

Session logs with the per-finding inputs, the final decision and aggregate token usage are saved to `logs/`.

## Testing

```bash
python -m pytest tests/ -v
```

## Benchmark

Compare model accuracy against human-reviewed findings:

```bash
python run_benchmark.py --model gemini-2.5-pro --output benchmark_results -v
```

Each dataset under `benchmark/datasets/<name>.json` must have a matching Gitleaks CSV at `benchmark/secret-reports/<name>.csv`; datasets without a matching report are skipped. See [docs/benchmark.md](docs/benchmark.md) for the dataset format, metrics and target thresholds.

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- [Architecture](docs/architecture.md): system overview, component map and the per-finding graph diagram.
- [Usage Guide](docs/usage-guide.md): CLI reference for both modes with examples, output schema and state derivation.
- [Preprocessing](docs/preprocessing.md): obfuscation and secret masking pipeline.
- [Configuration](docs/configuration.md): environment variables, constants and the per-finding graph configuration.
- [Benchmark](docs/benchmark.md): metrics, datasets, target thresholds and output format.
