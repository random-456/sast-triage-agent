# SAST Triage Agent

Automated triage of Checkmarx SAST findings using LangChain and LLM.

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
    "severity": "HIGH",
    "dataflow": [
        {"fileName": "/app/file.ts", "line": "152", "domType": "source"},
        {"fileName": "/app/file.ts", "line": "160", "domType": "sink"}
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