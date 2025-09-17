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

# LiteLLM Proxy Configuration
LLM_BASE_URL=http://localhost:4000
LLM_MODEL=gemini-2.5-pro
LLM_API_KEY=sk-1234
```

## Usage

```bash
python run_triage.py PROJECT_ID [OPTIONS]

# Examples:
python run_triage.py 12345                           # Analyze project with default settings
python run_triage.py 12345 --severities HIGH         # Only HIGH severity findings
python run_triage.py 12345 --output-dir ./analysis  # Custom output directory
```

Options:
- `--severities`: Comma-separated severities (default: HIGH,MEDIUM)
- `--output-dir`: Output directory (default: current directory)

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
    "findingId": "8ac6484c12c49772",
    "assessment_result": "CONFIRMED|NOT_EXPLOITABLE|REFUSED",
    "assessment_confidence": 0.85,
    "assessment_justification": "..."
}]
```

**triage_report.html**:
- Interactive HTML report with Tailwind CSS styling
- Progressive generation (updates after each finding)
- Sortable by severity, result, or confidence
- Filterable by assessment result
- Color-coded severity badges (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Grayscale styling for NOT_EXPLOITABLE findings
- Detailed dataflow visualization
- Real-time progress tracking

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

The test suite includes security tests, tool functionality tests and end-to-end integration tests.