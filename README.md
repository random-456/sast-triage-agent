# SAST Triage Agent

Automated triage of Checkmarx One SAST findings using LangChain and LLM. Fetches findings directly from Checkmarx API, clones repositories, and analyzes dataflow paths to make exploitability decisions.

## Setup

```bash
# (Recommended: Create a virtual environment)
pip install -r requirements.txt
cp .env.example .env
# Edit .env with individual settings
```

## Configuration

Edit `.env` file:
```env
# Checkmarx One Configuration
BASE_URL=https://
REFRESH_TOKEN=refresh-token

# Vertex AI Configuration
PROJECT_ID=gcp-project-id
DEFAULT_LOCATION=europe-west4
DEFAULT_MODEL=gemini-2.5-flash
```

**Prerequisites:**
- Access to Google Cloud Project with Vertex AI API enabled
- Application Default Credentials configured (`gcloud auth application-default login`)

## Usage

The CLI provides two sub-commands: `run` (non-interactive) and `interactive` (guided prompts).

### Non-interactive mode

```bash
python run_triage.py run PROJECT_NAME --gitleaks-report <path|none> [OPTIONS]

# Examples:
python run_triage.py run my-project --gitleaks-report none                          # Default settings
python run_triage.py run my-project --gitleaks-report report.csv --severities HIGH  # Only HIGH severity
python run_triage.py run my-project --gitleaks-report none --states TO_VERIFY,CONFIRMED
python run_triage.py run my-project --gitleaks-report none --branch main            # Specific branch
python run_triage.py run my-project --gitleaks-report none --findings <hash1>,<hash2>
```

Options:
- `--severities`: Comma-separated severities (default: HIGH,MEDIUM)
- `--states`: Comma-separated Checkmarx states (default: TO_VERIFY)
- `--output`: Output directory (default: output)
- `--branch`: Git branch to analyze (default: default.SecurityPipeline)
- `--findings`: Comma-separated result hashes (bypasses severity and state filters)
- `--gitleaks-report`: Path to Gitleaks CSV report, or 'none' (required)
- `--keep-temp`: Preserve the temp directory after execution
- `-v, --verbose`: Enable verbose output

### Interactive mode

```bash
python run_triage.py interactive [-v]
```

Guided prompts will collect project name, branch, scope, states, severities, model, Gitleaks path, and output directory. A configuration summary is displayed before execution, and preprocessing results are shown for confirmation.

## Output Structure

```
<output-dir>/
├── findings/
│   ├── triage_list.csv         # Finding IDs with severity and triage status
│   └── findings_details.json   # Detailed finding data with dataflow
├── codebase/                   # Cloned repository (if available)
├── findings_assessment.json    # Final triage decisions
├── triage_report.html          # Interactive HTML report with findings
└── triage_agent.log            # Execution log
```

## Results Format

**findings_assessment.json**:
```json
[{
    "resultHash": "8ac6484c12c49772",
    "assessment_result": "CONFIRMED|NOT_EXPLOITABLE|REFUSED",
    "assessment_confidence": 0.85,
    "assessment_justification": "..."
}]
```

**triage_report.html**:
- Interactive HTML report with Tailwind CSS styling
- Progressive generation (updates after each finding)
- Sortable by severity, result, confidence
- Filterable by assessment result
- Color-coded severity badges (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Grayscale styling for NOT_EXPLOITABLE findings
- Detailed dataflow visualization

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

The test suite includes security tests, tool functionality tests and end-to-end integration tests.

## Benchmark

A benchmark mode can be used to compare the accuracy of different models for triage of CheckmarxOne findings.

### Creating a benchmarking dataset

A ready-to-use dataset can be found in **benchmark/datasets**. Each project to use for the benchmark must have a separate file in this directory following the naming convention [CXONE PROJECT NAME].json and this format :

```json
{
    "project": "CXONE PROJECT NAME",
    "github_url": "GITHUB URL",
    "findings" : [
        {
            "id": "CXONE FINDING ID",
            "language": "LANGUAGE",
            "category": "CXONE FINDING TYPE",
            "severity": "CXONE FINDING SEVERITY",
            "complexity": "EASY / MEDIUM / COMPLEX",
            "analyst_triage": {
                "result": "CONFIRMED / NOT_EXPLOITABLE",
                "justification": "A brief justification for the result"
            }
        },
        ...
    ]
}
```

### Running a benchmark

```bash
Usage: run_benchmark.py [OPTIONS]

Options:
  --model TEXT   AI Model used for analysis
  --output TEXT  Output directory
  -v, --verbose  Enable verbose output
  --help         Show this message and exit.
```