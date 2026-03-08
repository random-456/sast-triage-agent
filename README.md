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

```bash
python run_triage.py PROJECT_NAME [OPTIONS]

# Examples:
python run_triage.py my-project                                    # Analyze project with default settings
python run_triage.py my-project --severities HIGH                  # Only HIGH severity findings
python run_triage.py my-project --output-dir ./analysis            # Custom output directory
python run_triage.py my-project --branch main                      # Analyze specific branch
python run_triage.py my-project --finding <cx_result_hash>         # Analyze a single finding by its result hash
```

Options:
- `--severities`: Comma-separated severities (default: HIGH,MEDIUM)
- `--output-dir`: Output directory (default: current directory)
- `--branch`: Git branch to analyze (default: default.SecurityPipeline)
- `--finding`: The Checkmarx result hash of a single finding to analyze

## Output Structure

```
<output-dir>/
├── findings/
│   ├── triage_list.csv          # Finding IDs with severity and triage status
│   └── findings_details.json    # Detailed finding data with dataflow
├── codebase/                    # Cloned repository (if available)
├── findings_assessment.json     # Final triage decisions
├── triage_report.html           # Interactive HTML report with findings
└── triage_agent.log             # Execution log
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
- `--model TEXT`    AI Model used for analysis
- `--output TEXT`   Output directory
- `-v, --verbose`   Enable verbose output
- `--help`          Show this message and exit.
```