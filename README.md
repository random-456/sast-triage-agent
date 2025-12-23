# SAST Triage Agent

Automated triage of Checkmarx One SAST findings using LangChain and LLM. Fetches findings directly from Checkmarx API, clones repositories, and analyzes dataflow paths to make exploitability decisions.

## How It Works

The agent uses a ReAct (Reasoning + Acting) pattern with verification:

1. Receives finding details including dataflow from Checkmarx API
2. Investigates using available tools (read files, search patterns, list directories)
3. Verifies analysis by articulating findings and identifying potential gaps
4. Submits triage decision with confidence score and justification

Available tools:
- `read_file` - Read source code files
- `search_in_files` - Search for patterns across codebase
- `list_directory` - Explore project structure
- `verify_analysis` - Verification checkpoint before final decision
- `submit_triage_decision` - Submit final triage result

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
DEFAULT_MODEL=gemini-2.5-pro
```

**Prerequisites:**
- Access to Google Cloud Project with Vertex AI API enabled
- Application Default Credentials configured (`gcloud auth application-default login`)

**Advanced Configuration (config.py):**
- `MAX_ANALYSIS_ITERATIONS`: Maximum agent iterations per finding (default: 30)
- `MAX_SEARCH_RESULTS`: Search result limit (default: 5000)
- `DEFAULT_SEVERITIES`: Default severity filters (default: HIGH, MEDIUM)

## Usage

```bash
python run_triage.py PROJECT_NAME [OPTIONS]
```

# Examples:
```
python run_triage.py my-project                              # Analyze project with default settings
python run_triage.py my-project --severities HIGH            # Only HIGH severity findings
python run_triage.py my-project --output ./analysis          # Custom output directory
python run_triage.py my-project --branch main                # Analyze specific branch
python run_triage.py my-project --findings <hash1>,<hash2>   # Analyze specific findings
```

Options:
- `--model`: AI model to use (default: gemini-2.5-pro)
- `--severities`: Comma-separated severities (default: HIGH,MEDIUM)
- `--output`: Output directory (default: output)
- `--branch`: Git branch to analyze (default: default.SecurityPipeline)
- `--findings`: Comma-separated result hashes to analyze specific findings
- `--keep-temp`: Keep temp directory after analysis
- `-v, --verbose`: Enable verbose logging

## Web UI

A FastAPI-based web interface for interactive triage analysis with real-time progress updates via WebSockets.

**📖 For detailed technical documentation, architecture, and design principles, see [Web UI Architecture](docs/WEB_UI_ARCHITECTURE.md)**

### Features

- **Finding Management**: Select and analyze findings of a Checkmarx project
- **Real-time Progress**: Live updates during analysis with latest action per finding
- **Session History**: View and manage historical analysis sessions
- **Write-back with Challenge**: Save triage decisions with optional override and justification
- **CSV Export**: Export analysis results to CSV format
- **Progressive Enhancement**: Table updates in place with color-coded results
  - Green: NOT_EXPLOITABLE
  - Red: CONFIRMED
  - Gray: REFUSED

### Running the Web UI

```bash
# Configure environment variables
cp .env.example .env

# Edit .env with required settings:
# - PROJECT_ID: Your GCP project ID
# - DEFAULT_LOCATION: Vertex AI location (default: us-central1)
# - BASE_URL: Checkmarx instance URL
# - REFRESH_TOKEN: Checkmarx API token

# Start the web server
python -m web_ui.main

# Access the UI at http://localhost:8765
```

### Workflow

1. **Fetch Findings**: Enter project name, branch, and filters (severity/state)
2. **Select Findings**: Check boxes to select findings for analysis
3. **Run Triage**: Click "Run Triage" to start background analysis with real-time updates
4. **Review Results**: View color-coded results with confidence scores and justifications
5. **Write-back**: Save decisions to session JSON (Checkmarx write-back is placeholder)
6. **Session Management**: Access historical sessions from the sidebar

### Technical Details

- **Port**: 8765 (configurable in `config.py`)
- **Concurrent Analyses**: 1 at a time (configurable via `MAX_CONCURRENT_ANALYSES`)
- **Session Storage**: JSON files in `web_sessions/` directory
- **Max Sessions**: 100 (configurable via `MAX_SESSION_HISTORY`)
- **WebSocket**: Automatic reconnection (up to 5 attempts)
- **Security**: Input validation, rate limiting, HTML escaping, localhost-only CORS

## Output Structure

```
<output-dir>/
├── findings/
│   ├── triage_list.csv                    # Finding IDs with severity and triage status
│   └── findings_details.json              # Detailed finding data with dataflow
├── codebase/                              # Cloned repository (if available)
├── logs/                                  # Detailed agent conversation logs (JSON)
├── findings_assessment_<project>.json     # Final triage decisions
└── triage_report_<timestamp>.html         # Interactive HTML report
```

## Results Format

**findings_assessment_<project>.json**:
```json
[{
    "resultHash": "8ac6484c12c49772",
    "assessment_result": "CONFIRMED|NOT_EXPLOITABLE|REFUSED",
    "assessment_confidence": 0.85,
    "assessment_justification": "..."
}]
```

**triage_report_<timestamp>.html**:
- Interactive HTML report with Tailwind CSS styling
- Sortable by severity, result, or confidence
- Filterable by assessment result
- Color-coded severity badges (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Detailed dataflow visualization

**logs/sast_triage_<timestamp>.json**:
- Complete agent conversation logs
- Tool calls and responses
- Decision-making process for each finding

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

The test suite includes security tests, tool functionality tests and end-to-end integration tests.

## Benchmark

A benchmark mode can be used to compare the accuracy of different models for triage of CheckmarxOne findings.

### Creating a benchmarking dataset

A ready-to-use dataset can be found in **benchmark/datasets**. Each project to use for the benchmark must have a separate file in this directory following the naming convention [CXONE_PROJECT_NAME].json and this format:

```json
{
    "project": "CXONE PROJECT NAME",
    "github_url": "GITHUB URL",
    "findings": [ {
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
- `--model TEXT`     AI Model used for analysis
- `--output TEXT`    Output directory
- `-v, --verbose`    Enable verbose output
- `--help`           Show this message and exit.
```