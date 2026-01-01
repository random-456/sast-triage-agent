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
        C[SASTTriageAgent<br/>LangChain + Vertex AI<br/>Gemini 2.5 Pro]
        D[Investigation Tools]
        E[read_file<br/>Read source files<br/>with line numbers]
        F[search_in_files<br/>Regex pattern search<br/>across codebase]
        G[list_directory<br/>Explore directory<br/>structure]
        H[Verification Checkpoint]
        I[verify_analysis<br/>MANDATORY pre-decision<br/>quality checkpoint]
        J[submit_triage_decision<br/>Final assessment<br/>with confidence]
    end

    subgraph "Iterative Investigation"
        K[Max 30 Iterations<br/>per Finding]
        L[LLM decides next action<br/>based on evidence]
        M[Tool-driven analysis<br/>until decision reached]
    end

    subgraph "Output Assessment"
        N[TriageDecision]
        O[CONFIRMED<br/>Exploitable vulnerability]
        P[NOT_EXPLOITABLE<br/>False positive]
        Q[REFUSED<br/>Insufficient information]
        R[Confidence Score<br/>0.0 to 1.0]
        S[Detailed Justification<br/>Analysis reasoning]
    end

    subgraph "Session Storage"
        T[session.json<br/>Complete analysis state<br/>+ statistics]
        U[findings_details.json<br/>Agent input data<br/>with dataflow]
        V[Conversation Logs<br/>Full tool usage<br/>audit trail]
    end

    A --> C
    B --> C
    C --> D
    D --> E
    D --> F
    D --> G
    D --> H
    H --> I
    I --> J
    C --> K
    K --> L
    L --> M
    M --> N
    N --> O
    N --> P
    N --> Q
    N --> R
    N --> S
    N --> T
    N --> U
    N --> V

    style A fill:#ffeaa7
    style B fill:#ffeaa7
    style C fill:#74b9ff
    style D fill:#81ecec
    style E fill:#55a3ff
    style F fill:#55a3ff
    style G fill:#55a3ff
    style H fill:#ff7675
    style I fill:#ff7675
    style J fill:#55a3ff
    style K fill:#fd79a8
    style L fill:#fd79a8
    style M fill:#fd79a8
    style O fill:#00b894
    style P fill:#e17055
    style Q fill:#fdcb6e
    style T fill:#a29bfe
    style U fill:#a29bfe
    style V fill:#a29bfe
```

## How It Works

1. **Session Initialization**: Creates isolated session directory with unique ID, fetches findings from Checkmarx One API, and clones target repository
2. **Finding Analysis**: For each untriaged finding, the AI agent:
   - Loads complete finding details including full dataflow from `findings_details.json`
   - Investigates source code using available tools (read files, search patterns, explore directories)
   - Performs up to 30 iterations of autonomous analysis
   - **Mandatory verification checkpoint** via `verify_analysis` tool before final decision
   - Submits final triage decision with confidence score and justification
3. **Tool Workflow**: Agent follows strict protocol:
   - Investigation tools: `read_file`, `search_in_files`, `list_directory`
   - Quality checkpoint: `verify_analysis` (mandatory - validates evidence and identifies gaps)
   - Final decision: `submit_triage_decision` (only after verification)
4. **Session Persistence**: All analysis results stored in session-specific `session.json` with real-time statistics tracking
5. **Audit Trail**: Complete conversation logs capture every tool invocation and LLM reasoning for full traceability

## Business Impact

- **Time Reduction**: 70-80% reduction in manual triage effort
- **Consistency**: Same analysis standards applied to every finding
- **Scalability**: Handles 100+ findings per scan automatically
- **Audit Trail**: Complete documentation of analysis reasoning

## Key Features

- **Session Isolation**: Each analysis run in dedicated session directory with unique ID
- **Security-First Design**: Path traversal protection, input validation, file locking for concurrent access
- **Quality Assurance**: Mandatory verification checkpoint prevents premature decisions
- **Enterprise Integration**: Works with existing Checkmarx workflows via REST API
- **Flexible Configuration**: Supports severity filtering, branch selection, individual finding analysis
- **Real-Time Tracking**: Session statistics updated incrementally with analysis progress
- **Complete Audit Trail**: Full conversation logs with tool usage for compliance and debugging