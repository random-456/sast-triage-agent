# Usage Guide

The CLI provides two modes of operation: `run` (non-interactive) and `interactive` (guided prompts).

## Non-Interactive Mode

```bash
python run_triage.py run PROJECT_NAME --gitleaks-report <path|none> [OPTIONS]
```

`PROJECT_NAME` is the exact Checkmarx One project name. The `--gitleaks-report` flag is required and accepts either a path to a Gitleaks CSV file or `none` to skip secret masking.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--model` | `gemini-2.5-pro` | AI model for analysis |
| `--severities` | `HIGH,MEDIUM` | Comma-separated severity filter |
| `--states` | `TO_VERIFY` | Comma-separated Checkmarx state filter |
| `--branch` | `default.SecurityPipeline` | Git branch to analyze |
| `--findings` | -- | Comma-separated result hashes (bypasses severity/state filters) |
| `--gitleaks-report` | -- | Path to Gitleaks CSV, or `none` (required) |
| `--output` | `output` | Output directory |
| `--keep-temp` | `false` | Preserve temp directory after execution |
| `--trace` | `false` | Enable Phoenix tracing UI at localhost:6006 |
| `-v, --verbose` | `false` | Enable debug-level logging |

### Examples

Basic run with default settings:
```bash
python run_triage.py run my-project --gitleaks-report none
```

Filter by severity and state:
```bash
python run_triage.py run my-project --gitleaks-report none --severities HIGH --states TO_VERIFY,CONFIRMED
```

Analyze specific findings by hash:
```bash
python run_triage.py run my-project --gitleaks-report none --findings abc123,def456
```

With Gitleaks secret masking and a specific branch:
```bash
python run_triage.py run my-project --gitleaks-report gitleaks-report.csv --branch main
```

With verbose output and Phoenix tracing:
```bash
python run_triage.py run my-project --gitleaks-report none -v --trace
```

Using a Claude model on Vertex AI:
```bash
python run_triage.py run my-project --gitleaks-report none --model claude-sonnet-4-5
```

## Interactive Mode

```bash
python run_triage.py interactive [-v] [--trace]
```

Interactive mode presents guided prompts to collect all configuration:

1. **Project name** -- Checkmarx project name (required)
2. **Branch** -- Git branch to analyze (default: `default.SecurityPipeline`)
3. **Analysis scope** -- Choose between filtering all findings or targeting specific hashes
4. **States** -- Checkmarx states to include (checkbox selection)
5. **Severities** -- Severity levels to include (checkbox selection)
6. **Model** -- AI model name (default: `gemini-2.5-pro`)
7. **Gitleaks report** -- Path to CSV or `none`
8. **Output directory** -- Where to save results (default: `output`)

After collecting inputs, a configuration summary is displayed for confirmation. If the codebase is cloned and preprocessed successfully, a preprocessing summary shows obfuscation and masking results before proceeding with the actual analysis.

## Filtering Behavior

### Severity Filter

The `--severities` option filters findings during the Checkmarx API fetch. Only findings matching the specified severities are retrieved. Valid values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

### State Filter

The `--states` option applies a client-side filter after findings are fetched. Only findings with a matching Checkmarx state are included for analysis. Valid values: `TO_VERIFY`, `NOT_EXPLOITABLE`, `PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`, `URGENT`.

### Finding Hashes

When `--findings` is provided, both severity and state filters are bypassed. Only findings whose result hash matches one of the provided values are analyzed.

## Output

Results are saved to a timestamped JSON file in the output directory:

```
output/
    findings_assessment_<project>_<timestamp>.json
```

The file contains:

```json
{
  "metadata": {
    "project_name": "my-project",
    "project_id": "...",
    "scan_id": "...",
    "branch": "main",
    "model": "gemini-2.5-pro",
    "timestamp": "2026-03-11T14:30:00",
    "total_findings": 5,
    "summary": {
      "confirmed": 2,
      "not_exploitable": 2,
      "refused": 1
    }
  },
  "results": [
    {
      "resultHash": "abc123",
      "assessment_result": "CONFIRMED",
      "assessment_confidence": 0.92,
      "assessment_justification": "..."
    }
  ]
}
```

### Assessment Results

| Result | Meaning |
|--------|---------|
| `CONFIRMED` | The finding is a true positive (exploitable vulnerability) |
| `NOT_EXPLOITABLE` | The finding is a false positive (not exploitable) |
| `REFUSED` | The agent could not make a determination (manual review required) |

### Session Logs

Each run produces a session log in the `logs/` directory with the full conversation history, token usage, and preprocessing reports. See [architecture.md](architecture.md) for details on the log structure.

## Phoenix Tracing

When `--trace` is passed (or `SAST_TRIAGE_TRACE=true` is set), the agent starts a local Phoenix server for LLM observability. After analysis completes, the process blocks and displays:

```
Phoenix tracing UI is available at http://localhost:6006
Press Enter to stop Phoenix and exit...
```

This allows reviewing traces in the Phoenix UI before the process exits. Tracing requires optional dependencies:

```bash
pip install arize-phoenix openinference-instrumentation-langchain
```

## Benchmarking

A separate benchmark mode compares model accuracy against human-reviewed findings:

```bash
python run_benchmark.py --model gemini-2.5-pro --output benchmark_results -v
```

> **Note:** Benchmark runs skip Gitleaks secrets masking (`--gitleaks-report none`) to focus purely on triage accuracy.

Benchmark datasets are stored in `benchmark/datasets/` as JSON files. Each file contains findings with analyst-provided ground truth decisions. See the [README](../README.md) for dataset format details.
