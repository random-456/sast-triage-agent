# SAST Triage Agent - Functional Overview

## Problem Statement

Security scanners like Checkmarx generate hundreds of potential vulnerabilities per application scan. Security teams spend 70-80% of their time manually reviewing these findings to determine which ones are actually exploitable and require immediate action.

## Solution Architecture

```mermaid
graph TB
    subgraph "Input Data"
        A[Checkmarx One<br/>SAST Findings<br/>+ Dataflow Details]
        B[Git Repository<br/>Source Code<br/>Complete Codebase]
    end

    subgraph "AI Analysis Engine"
        C[SASTTriageAgent<br/>LangChain + Vertex AI<br/>Gemini 2.5 Flash]
        D[Analysis Tools]
        E[read_file<br/>Read any source file<br/>with line numbers]
        F[search_in_files<br/>Pattern search across<br/>entire codebase]
        G[list_directory<br/>Explore project<br/>structure]
        H[submit_triage_decision<br/>Final assessment<br/>with confidence]
    end

    subgraph "Iterative Investigation"
        I[Max 15 Iterations<br/>per Finding]
        J[LLM decides next action<br/>based on evidence found]
        K[Comprehensive analysis<br/>until decision reached]
    end

    subgraph "Output Assessment"
        L[TriageDecision]
        M[CONFIRMED<br/>Exploitable vulnerability]
        N[NOT_EXPLOITABLE<br/>False positive]
        O[REFUSED<br/>Insufficient information]
        P[Confidence Score<br/>0.0 to 1.0]
        Q[Detailed Justification<br/>Analysis reasoning]
    end

    subgraph "Generated Reports"
        R[findings_assessment.json<br/>Structured results]
        S[triage_report.html<br/>Interactive report]
        T[Updated CSV<br/>Triage status]
    end

    A --> C
    B --> C
    C --> D
    D --> E
    D --> F
    D --> G
    D --> H
    C --> I
    I --> J
    J --> K
    K --> L
    L --> M
    L --> N
    L --> O
    L --> P
    L --> Q
    L --> R
    L --> S
    L --> T

    style A fill:#ffeaa7
    style B fill:#ffeaa7
    style C fill:#74b9ff
    style D fill:#81ecec
    style E fill:#55a3ff
    style F fill:#55a3ff
    style G fill:#55a3ff
    style H fill:#55a3ff
    style I fill:#fd79a8
    style J fill:#fd79a8
    style K fill:#fd79a8
    style M fill:#00b894
    style N fill:#e17055
    style O fill:#fdcb6e
    style R fill:#a29bfe
    style S fill:#a29bfe
    style T fill:#a29bfe
```

## How It Works

1. **Data Collection**: Fetches findings from Checkmarx One API and clones the target repository
2. **Finding Analysis**: For each untriaged finding, the AI agent:
   - Loads complete finding details including dataflow
   - Uses available tools to investigate the codebase
   - Performs up to 15 iterations of analysis
   - Makes evidence-based triage decision
3. **Tool Capabilities**: The AI can read any file, search patterns across the codebase, explore directories, and submit final decisions
4. **Output Generation**: Creates structured assessments and interactive HTML reports
5. **Incremental Processing**: Saves results immediately and can resume from interruptions

## Business Impact

- **Time Reduction**: 70-80% reduction in manual triage effort
- **Consistency**: Same analysis standards applied to every finding
- **Scalability**: Handles 100+ findings per scan automatically
- **Audit Trail**: Complete documentation of analysis reasoning

## Key Features

- **Security-First Design**: Path traversal protection, input validation
- **Enterprise Integration**: Works with existing Checkmarx workflows
- **Flexible Configuration**: Supports different severities, branches, single findings
- **Progressive Reporting**: Updates HTML report after each finding analysis