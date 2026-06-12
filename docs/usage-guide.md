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
| `--model` | config default | Model for all LLM nodes; overrides the config defaults |
| `--research-model` | config default | Model for the research node (overrides `--model`) |
| `--analyst-model` | config default | Model for the analyst node (overrides `--model`) |
| `--critic-model` | config default | Model for the critic node (overrides `--model`) |
| `--research-location` | global location | Vertex region for the research node |
| `--analyst-location` | global location | Vertex region for the analyst node |
| `--critic-location` | global location | Vertex region for the critic node |
| `--severities` | `HIGH,MEDIUM` | Comma-separated severity filter |
| `--states` | `TO_VERIFY` | Comma-separated Checkmarx state filter |
| `--branch` | `default.SecurityPipeline` | Git branch to analyze |
| `--findings` | -- | Comma-separated result hashes (bypasses severity/state filters) |
| `--gitleaks-report` | -- | Path to Gitleaks CSV, or `none` (required) |
| `--output` | `output` | Output directory |
| `--run-subdir/--no-run-subdir` | `--run-subdir` | Nest this run's results under a timestamped subfolder of `--output` |
| `--keep-temp` | `false` | Preserve temp directory after execution |
| `--log-mode` | `rich` | Session log capture: `rich` records every LLM prompt and response (sufficient for replay); `observability` replaces content with hashes and lengths. |
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

Using a faster, lower-cost model for every node:
```bash
python run_triage.py run my-project --gitleaks-report none --model gemini-2.5-flash
```

Running Gemini for research and analyst, Claude for the critic:
```bash
python run_triage.py run my-project --gitleaks-report none \
  --critic-model claude-sonnet-4@20250514 --critic-location us-east5
```

## Interactive Mode

```bash
python run_triage.py interactive [-v]
```

Interactive mode presents guided prompts to collect all configuration:

1. **Project name:** Checkmarx project name (required).
2. **Branch:** git branch to analyze (default: `default.SecurityPipeline`).
3. **Analysis scope:** choose between filtering all findings or targeting specific hashes.
4. **States:** Checkmarx states to include (checkbox selection).
5. **Severities:** severity levels to include (checkbox selection).
6. **Model:** model name applied to all nodes (default: `gemini-2.5-pro`). Per-node models are set via the `run` flags or config.py.
7. **Gitleaks report:** path to CSV or `none`.
8. **Output directory:** where to save results (default: `output`).

After collecting inputs, a configuration summary is displayed for confirmation. If the codebase is cloned and preprocessed successfully, a preprocessing summary shows obfuscation and masking results before proceeding with the actual analysis.

## Filtering Behavior

### Severity Filter

The `--severities` option filters findings during the Checkmarx API fetch. Only findings matching the specified severities are retrieved. Valid values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

### State Filter

The `--states` option applies a client-side filter after findings are fetched. Only findings with a matching Checkmarx state are included for analysis. Valid values: `TO_VERIFY`, `NOT_EXPLOITABLE`, `PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`, `URGENT`.

### Finding Hashes

When `--findings` is provided, both severity and state filters are bypassed. Only findings whose result hash matches one of the provided values are analyzed.

## Output

Results are saved to a timestamped JSON file. By default each run gets its own
timestamped subfolder so repeated runs stay grouped:

```
output/
    <timestamp>/
        findings_assessment_<project>_<timestamp>.json
```

Pass `--no-run-subdir` to write directly into `--output` instead.

The file contains:

```json
{
  "metadata": {
    "project_name": "my-project",
    "project_id": "...",
    "scan_id": "...",
    "branch": "main",
    "models": {
      "research": "gemini-2.5-pro",
      "analyst": "gemini-2.5-pro",
      "critic": "gemini-2.5-pro"
    },
    "timestamp": "2026-03-11T14:30:00",
    "total_findings": 5,
    "summary": {
      "confirmed": 2,
      "not_exploitable": 1,
      "proposed_not_exploitable": 1,
      "refused": 1,
      "refusal_rate": 0.2
    }
  },
  "results": [
    {
      "resultHash": "abc123",
      "is_vulnerable": true,
      "confidence": 0.92,
      "suggested_state": "CONFIRMED",
      "justification": "..."
    }
  ]
}
```

Each result separates the classification (`is_vulnerable` plus `confidence`) from the advisory disposition (`suggested_state`). The tool only reads from Checkmarx One; every `suggested_state` is a recommendation written to the local output file and is never written back to Checkmarx.

### Classification

| `is_vulnerable` | Meaning |
|-----------------|---------|
| `true` | The finding is exploitable (true positive) |
| `false` | The finding is not exploitable (false positive) |
| `null` | The agent could not decide |

### Suggested State

`suggested_state` is derived from the classification and confidence. A non-exploitable verdict below `CONFIDENCE_THRESHOLD` is escalated to `PROPOSED_NOT_EXPLOITABLE` rather than dismissed.

| Suggested State | Derivation |
|-----------------|------------|
| `CONFIRMED` | `is_vulnerable` is `true` (always surfaced, regardless of confidence) |
| `NOT_EXPLOITABLE` | `is_vulnerable` is `false` and confidence is at or above the threshold |
| `PROPOSED_NOT_EXPLOITABLE` | `is_vulnerable` is `false` and confidence is below the threshold (flagged for human review) |
| `REFUSED` | `is_vulnerable` is `null` (manual review required) |

### Session Logs

Each run produces a session log in the `logs/` directory containing the per-finding inputs and selected checklist, the final decision and aggregate token usage. See [architecture.md](architecture.md#session-logging) for the log structure.

## Benchmarking

A separate benchmark mode compares model accuracy against human-reviewed findings. See [benchmark.md](benchmark.md) for the full runbook, dataset format, metrics and target thresholds.
