# SAST Triage Agent - LangChain + Gemini

An intelligent agent for automated triage of Checkmarx SAST findings using LangChain and Google Gemini.

## Features

- **Automated Triage**: Analyzes each SAST finding to determine if it's a true positive or false positive
- **Deep Code Analysis**: Traces complete dataflow from source to sink
- **Confidence Scoring**: Provides confidence levels (0-1) for each decision
- **Detailed Justification**: Explains reasoning behind each triage decision
- **CSV Progress Tracking**: Updates triage status in real-time
- **Comprehensive Analysis**: Considers:
  - Component context and interactions
  - Data flow across trust boundaries
  - Existing security controls
  - Exploitation potential (including privileged attackers)

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure LLM Endpoint

The agent uses an OpenAI-compatible endpoint (perfect for LiteLLM proxy with Vertex AI):

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your settings
nano .env
```

Or set environment variables directly:
```bash
export LLM_BASE_URL='http://localhost:4000'
export LLM_MODEL='gemini-2.0-flash-exp'
export LLM_API_KEY='dummy-key'
```

For LiteLLM with Vertex AI, start your proxy:
```bash
litellm --model vertex_ai/gemini-2.0-flash-exp --port 4000
```

### 3. Prepare Directory Structure

```
project/
├── findings/
│   ├── triage_list.csv         # List of findings to triage
│   └── findings_details.json   # Detailed finding information
├── /codebase/                  # Source code to analyze
├── sast_triage_agent.py        # Main agent implementation
├── run_triage.py               # Runner script
└── findings_assessment.json    # Output (generated)
```

### 4. Input File Formats

#### triage_list.csv
```csv
findingId,severity,triaged
8ac6484c65c49772,HIGH,no
9ui9316uww0i9e9j,HIGH,no
```

#### findings_details.json
```json
[
    {
        "findingId": "8ac6484c65c49772",
        "category": "JavaScript_Angular",
        "cweID": 79,
        "languageName": "javascript",
        "queryName": "Angular_Client_DOM_XSS",
        "severity": "HIGH",
        "dataflow": [
            {
                "column": "62",
                "fileName": "/frontend/src/app/search-result.component.ts",
                "line": "152",
                "method": "filterTable",
                "name": "q",
                ...
            }
        ]
    }
]
```

## Usage

### Simple Run

```bash
python run_triage.py
```

### Direct Python Usage

```python
import asyncio
from sast_triage_agent import SASTTriageAgent

async def analyze():
    agent = SASTTriageAgent(
        base_url="http://localhost:4000",  # Your LiteLLM proxy
        model_name="gemini-2.0-flash-exp",  # Model as configured in proxy
        api_key="dummy-key",
        temperature=0.1
    )
    
    results = await agent.process_all_findings(
        csv_path="findings/triage_list.csv",
        json_path="findings/findings_details.json"
    )
    
    return results

# Run the analysis
results = asyncio.run(analyze())
```

## Output Format

The agent generates `findings_assessment.json` with the following structure:

```json
[
    {
        "findingId": "8ac6484c65c49772",
        "assessment_result": "CONFIRMED",
        "assessment_confidence": 0.85,
        "assessment_justification": "Detailed explanation..."
    }
]
```

### Assessment Results

- **CONFIRMED**: True positive vulnerability (even if exploitation is difficult)
- **NOT_EXPLOITABLE**: False positive with strong evidence of mitigation
- **REFUSED**: Insufficient information for confident decision

### Confidence Scores

- **0.8-1.0**: High confidence in decision
- **0.5-0.79**: Medium confidence
- **0.0-0.49**: Low confidence (consider manual review)

## How It Works

1. **Parse Findings**: Reads CSV list and JSON details
2. **Analyze Each Finding**:
   - Retrieves detailed finding information
   - Traces complete dataflow path
   - Examines code at critical points
   - Checks for existing security controls
   - Evaluates exploitation potential
3. **Make Decision**: Based on comprehensive analysis
4. **Update Progress**: Marks findings as triaged in CSV
5. **Generate Report**: Creates structured JSON output

## Key Features

### Deep Dataflow Analysis
The agent traces the complete path from user input (source) to dangerous operation (sink), analyzing each step for:
- User input detection
- Data transformations
- Sanitization functions
- Trust boundary crossings

### Context-Aware Analysis
Considers:
- Component's role in the system
- Interaction patterns
- Business logic context
- Existing security measures

### Intelligent Decision Making
- Recognizes common false positive patterns
- Identifies real vulnerabilities even with high exploitation difficulty
- Considers attack scenarios including privileged attackers
- Provides detailed justification for each decision

## Customization

### Model Selection
Change the Gemini model in `SASTTriageAgent`:
```python
agent = SASTTriageAgent(
    model_name="gemini-2.0-flash-exp",  # or "gemini-1.5-pro"
    temperature=0.1  # Lower = more consistent
)
```

### Analysis Depth
Adjust `max_iterations` for thoroughness:
```python
self.agent_executor = AgentExecutor(
    agent=self.agent,
    tools=self.tools,
    max_iterations=15,  # Increase for deeper analysis
    verbose=True
)
```

## Troubleshooting

### Code Base Mismatch
If all findings are REFUSED with "Code base and findings report do not match":
- Verify `/codebase` contains the correct source code
- Check that file paths in findings match actual file structure
- Ensure code version matches when findings were generated

### API Rate Limits
If hitting Gemini API limits:
- Add delays between findings
- Use batch processing
- Consider upgrading API quota

### Low Confidence Scores
For consistently low confidence:
- Ensure complete codebase is available
- Check that dataflow information is complete
- Consider increasing analysis iterations

## Security Notes

- Agent operates in read-only mode
- Never modifies source code
- Focuses on defensive security analysis
- Designed for internal use by security teams

## License

Proprietary - For internal use only