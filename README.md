# SAST Triage Agent

Automated triage of Checkmarx One SAST findings using LangChain and LLM. The agent analyzes dataflow paths, reads source code files, searches for patterns and makes exploitability decisions based on code context.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your LLM endpoint settings
```

## Directory Structure

```
project/
├── findings/
│   ├── triage_list.csv
│   └── findings_details.json  
└── codebase/
    └── (source code)
```

## Usage

```bash
python run_triage.py [project_directory]
```

Creates `findings_assessment.json` with triage decisions.

## Input Format

**triage_list.csv**:
```csv
findingId,severity,triaged
8ac6484c65c49772,HIGH,no
```

**findings_details.json**:
```json
[{
    "findingId": "8ac6484c65c49772",
    "queryName": "Angular_Client_DOM_XSS",
    "cweID": 79,
    "severity": "HIGH",
    "dataflow": [
        {
            "fileName": "/frontend/src/app/search-result.component.ts",
            "line": "152",
            "column": "62", 
            "method": "filterTable",
            "name": "q",
            "nodeID": 1,
            "domType": "source"
        },
        {
            "fileName": "/frontend/src/app/search-result.component.ts",
            "line": "160",
            "column": "18",
            "method": "filterTable", 
            "name": "innerHTML",
            "nodeID": 2,
            "domType": "sink"
        }
    ]
}]
```

## Output

```json
[{
    "findingId": "8ac6484c65c49772",
    "assessment_result": "CONFIRMED|NOT_EXPLOITABLE|REFUSED",
    "assessment_confidence": 0.85,
    "assessment_justification": "..."
}]
```