# SAST Triage Agent

Automated triage of Checkmarx SAST findings using LangChain and Google Gemini.

## Setup

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure LLM Endpoint

Set environment variables:
```bash
export LLM_BASE_URL='http://localhost:4000'
export LLM_MODEL='gemini-2.5-pro'
export LLM_API_KEY='dummy-key'
```

Or use `.env` file:
```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Directory Structure

Your project directory should contain:
```
my_project/
├── findings/
│   ├── triage_list.csv
│   └── findings_details.json  
└── codebase/
    └── (your source code)
```

After running the analysis, output is created:
```
my_project/
├── findings/
├── codebase/
└── findings_assessment.json  ← created here
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
                "nodeID": 1,
                "domType": "source"
            },
            {
                "column": "18",
                "fileName": "/frontend/src/app/search-result.component.ts", 
                "line": "160",
                "method": "filterTable",
                "name": "innerHTML",
                "nodeID": 2,
                "domType": "sink"
            }
        ]
    }
]
```

## Usage

```bash
# Use current directory
python run_triage.py

# Specify project directory
python run_triage.py ./my_project

# Use absolute path
python run_triage.py /path/to/context
```

## Output Format

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

- **CONFIRMED**: True positive vulnerability
- **NOT_EXPLOITABLE**: False positive 
- **REFUSED**: Insufficient information

### Confidence Scores

- **0.8-1.0**: High confidence
- **0.5-0.79**: Medium confidence  
- **0.0-0.49**: Low confidence

## How It Works

1. Parse CSV findings list and JSON details
2. For each finding:
   - Trace dataflow from source to sink
   - Examine code at critical points
   - Check for security controls
   - Evaluate exploitation potential
3. Generate structured assessment with confidence score