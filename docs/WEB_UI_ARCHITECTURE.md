# Web UI Architecture

## Overview

The Web UI is a FastAPI-based local web interface for the SAST Triage Agent. It provides an interface for triaging Checkmarx SAST findings with real-time progress updates.

**Important**: This is a **local development tool** designed for rapid prototyping and internal demonstrations. It is **not the target production architecture**, which will eventually be a cloud-deployed solution.

## Table of Contents

- [Architecture](#architecture)
- [Design Principles](#design-principles)
- [Technical Implementation](#technical-implementation)
- [Session Storage](#session-storage)
- [WebSocket Communication](#websocket-communication)
- [Security](#security)
- [Development Notes](#development-notes)
- [Troubleshooting](#troubleshooting)

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Browser                             │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │  HTML/CSS/JS   │  │  WebSocket   │  │  State Manager  │  │
│  │  (Tailwind)    │  │  Client      │  │  (Pub/Sub)      │  │
│  └────────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │                    │
                      REST API              WebSocket
                          │                    │
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    API Endpoints                       │ │
│  │  /api/projects  /api/findings  /api/analysis  /ws      │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                   Services Layer                       │ │
│  │  - CheckmarxService   - AnalysisService                │ │
│  │  - SessionStorage     - WebSocketManager               │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Security Middleware                       │ │
│  │  - Input Validation  - Rate Limiting  - CORS           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────────┐
│                   Core Agent (Reused)                       │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ SASTTriageAgent│  │ AgentLogging │  │  Agent Tools    │  │
│  │ (w. callbacks) │  │              │  │  (read, search) │  │
│  └────────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────────┐
│                 External Dependencies                       │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Checkmarx API  │  │  Vertex AI   │  │  Git Repos      │  │
│  │ (findings)     │  │  (LLM)       │  │  (codebase)     │  │
│  └────────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

**Frontend (Browser)**:
- Single-page application with progressive enhancement
- Renders UI, handles user interactions
- Manages client-side state (StateManager)
- WebSocket client for real-time updates

**API Layer**:
- REST endpoints for CRUD operations
- WebSocket endpoint for real-time communication
- Input validation and sanitization
- Rate limiting

**Services Layer**:
- **AnalysisService**: Orchestrates background analysis, manages concurrent tasks
- **SessionStorage**: JSON file I/O operations
- **WebSocketManager**: Manages WebSocket connections, broadcasts messages
- **CheckmarxService**: Wraps Checkmarx API client

**Core Agent**:
- Reused from CLI tool (95% code reuse)
- Modified to support progress callbacks
- Performs triage analysis using LLM

---

## Design Principles

### 1. **Database-Free Architecture**

**Rationale**: This is a local tool for quick demonstrations and internal use. Adding a database (PostgreSQL, SQLite, etc.) would introduce complexity and deployment overhead that is not necessary for the current use case.

**Implementation**: All session data is stored in JSON files (`analysis_sessions/{session_id}/session.json`), with an index file for listing.

**Characteristics**:
- Zero setup requirement
- Portable across systems
- Human-readable format
- Simple debugging
- Not designed for high concurrency
- Limited querying capabilities

**Future**: Production architecture will use a database (PostgreSQL/MongoDB).

---

### 2. **Minimal Code Modification**

**Rationale**: The CLI tool's core logic (`sast_triage/agent.py`, `utils/checkmarx_helpers.py`) is already implemented and tested. Reusing it minimizes changes and potential bugs.

**Implementation**:
- Added progress callbacks to agent (7 event emission points)
- Made HTML report generation optional
- Added state parameter to Checkmarx API calls
- No other changes to core logic

**Code Reuse**: 95% of existing codebase reused.

---

### 3. **Security-First Design**

**Rationale**: Local tools must be secure to prevent accidental exposure or misuse.

**Implementation**:
- Input validation with regex patterns and whitelists
- HTML escaping for all user-generated content
- Rate limiting on expensive endpoints
- CORS restricted to localhost only
- Path traversal prevention
- No secrets in code (environment variables)

**Details**: See [Security](#security) section.

---

### 4. **Progressive Enhancement**

**Rationale**: UI transitions should be minimal. Users see their selections update in place rather than full screen changes.

**Implementation**:
- Same table element used across all screens
- Rows progressively update with spinners then results
- Color-coded backgrounds applied on completion
- No page reloads or screen replacements

---

### 5. **Real-Time Updates via WebSockets**

**Rationale**: Polling introduces inefficiency and lag. WebSockets provide instant bidirectional communication.

**Implementation**:
- WebSocket connection per session
- Server broadcasts 6 event types: `analysis_started`, `analysis_progress`, `tool_execution`, `analysis_complete`, `analysis_failed`, `batch_progress`
- Automatic reconnection (up to 5 attempts)
- Multi-tab support (multiple connections per session)

**Details**: See [WebSocket Communication](#websocket-communication) section.

---

### 6. **Background Analysis**

**Rationale**: Analysis can take 30-60 seconds per finding. Blocking the main thread would freeze the UI.

**Implementation**:
- Analysis runs in `asyncio.create_task()` background task
- Continues even if browser closes
- Progress tracked in session JSON
- User can reconnect and see updated state

**Concurrency Limit**: 1 concurrent analysis at a time (configurable via `MAX_CONCURRENT_ANALYSES`).

---

### 7. **Localhost-Only Deployment**

**Rationale**: This tool requires access to:
- Checkmarx API tokens (sensitive)
- Google Cloud credentials (sensitive)
- Cloned git repositories (potentially proprietary code)

Running remotely would require implementing:
- User authentication
- Multi-tenancy
- Encrypted credential storage
- Network security

**Current Implementation**: Binds to `127.0.0.1` only, CORS restricted to localhost.

**Future**: Cloud deployment will require full authentication/authorization system.

---

## Technical Implementation

### Technology Stack

**Backend**:
- **FastAPI**: Async web framework with native WebSocket support
- **Pydantic**: Type-safe request/response validation
- **uvicorn**: ASGI server
- **LangChain**: Agent framework (reused from CLI)
- **Vertex AI**: LLM provider (Gemini models)

**Frontend**:
- **Vanilla JavaScript**: No framework dependencies
- **Tailwind CSS**: Utility-first CSS (CDN)
- **Font Awesome**: Icon library (CDN)
- **WebSocket API**: Native browser WebSocket support

**Storage**:
- **JSON files**: Session persistence
- **File system**: Session index

---

### Directory Structure

```
web_ui/
├── __init__.py
├── main.py                         # Entry point (uvicorn runner)
├── app.py                          # FastAPI application
│
├── models/                         # Pydantic models
│   ├── request_models.py           # API request schemas
│   ├── response_models.py          # API response schemas
│   └── session_models.py           # Session data models
│
├── services/                       # Business logic
│   ├── analysis_service.py         # Orchestrates triage analysis
│   ├── checkmarx_service.py        # Wraps CheckmarxClient
│   ├── session_storage.py          # JSON file operations
│   └── websocket_manager.py        # WebSocket connection management
│
├── api/                            # API endpoints
│   ├── projects.py                 # Project search
│   ├── analysis.py                 # Analysis start/status/retry
│   ├── sessions.py                 # Session CRUD, CSV export
│   └── websocket.py                # WebSocket endpoint
│
├── middleware/                     # Security layer
│   ├── security.py                 # Input validation, sanitization
│   └── rate_limiter.py             # Rate limiting
│
├── static/                         # Frontend assets
│   ├── css/custom.css
│   └── js/
│       ├── app.js                  # Main application
│       ├── websocket-client.js     # WebSocket client
│       ├── state-manager.js        # Client state management
│       └── components/
│           ├── sidebar.js
│           ├── findings-table.js
│           ├── analysis-modal.js
│           └── writeback-modal.js
│
└── templates/
    └── index.html                  # Single-page application
```

---

## Session Storage

### JSON File Structure

**Location**: `analysis_sessions/{session_id}/session.json`

**Session ID Format**: `YYYYMMDD_HHMMSS_{random_6chars}`

**Example**: `analysis_sessions/20251223_143052_a1b2c3/session.json`

### Session Schema

```json
{
  "session_id": "20251223_143052_a1b2c3",
  "created_at": "2025-12-23T14:30:52Z",
  "updated_at": "2025-12-23T14:35:20Z",
  "status": "completed",

  "metadata": {
    "project_name": "my-api",
    "project_id": "proj-uuid",
    "scan_id": "scan-uuid",
    "branch": "main",
    "github_url": "https://github.com/org/repo",
    "checkmarx_base_url": "https://checkmarx.company.com",
    "model_name": "gemini-2.5-pro",
    "severity_filters": ["HIGH", "MEDIUM"],
    "status_filters": ["TO_VERIFY"]
  },

  "findings": [
    {
      "resultHash": "abc123",
      "category": "SQL_Injection",
      "cweID": "CWE-89",
      "languageName": "Java",
      "queryName": "SQL_Injection",
      "severity": "HIGH",
      "state": "TO_VERIFY",
      "checkmarx_url": "https://checkmarx.../results/abc123",
      "dataflow": [...],

      "analysis": {
        "status": "completed",
        "started_at": "2025-12-23T14:31:00Z",
        "completed_at": "2025-12-23T14:31:45Z",
        "duration_seconds": 45.2,
        "iterations_used": 8,
        "result": "CONFIRMED",
        "confidence": 0.85,
        "justification": "...",
        "last_action": "Reading authentication module...",
        "conversation_log": [
          {"type": "system", "content": "..."},
          {"type": "assistant", "content": "..."},
          {"type": "tool", "tool_name": "read_file", "result": "..."}
        ]
      },

      "writeback": {
        "saved": false,
        "saved_at": null,
        "decision": "CONFIRMED",
        "justification": "...",
        "user_override": null
      }
    }
  ],

  "statistics": {
    "total_findings": 15,
    "analyzed_count": 12,
    "pending_count": 3,
    "confirmed_count": 3,
    "not_exploitable_count": 8,
    "refused_count": 1,
    "high_confidence_count": 7,
    "avg_confidence": 0.82,
    "avg_duration_seconds": 38.5
  }
}
```

### Session Management

**Creation**: When user clicks "Fetch Findings", creates new session folder with session.json.

**Updates**: After each finding analysis completes, session JSON is saved.

**Listing**: Index file `analysis_sessions/sessions_index.json` stores metadata for fast listing.

**Limit**: Maximum 100 sessions (configurable via `MAX_SESSION_HISTORY`).

**Cleanup**:
- **WebUI**: Sessions persist until manually deleted by user (click X button)
- **CLI**: Only `codebase/` folder deleted after analysis; session results persist
- **Automatic**: Oldest sessions deleted when limit exceeded (100 sessions)

### CLI vs WebUI Session Handling

Both CLI and WebUI use the unified session architecture in `analysis_sessions/`:

| Aspect | CLI | WebUI |
|--------|-----|-------|
| **Session Creation** | Creates new session for each run | Creates new session via UI |
| **Index Registration** | Adds to `sessions_index.json` | Adds to `sessions_index.json` |
| **Results Storage** | Updates `session.json` after each finding | Updates `session.json` after each finding |
| **Codebase Cleanup** | Deletes `codebase/` folder after completion | Keeps `codebase/` for incremental analysis |
| **Session Persistence** | Session persists (without codebase) | Session persists until manual deletion |
| **Resumability** | Cannot resume (codebase deleted) | Can resume analysis anytime |

**Why CLI Deletes Codebase:**
- CLI analyzes all selected findings in one batch
- After analysis completes, codebase is no longer needed
- Saves significant disk space for large repositories
- Session results remain accessible via `session.json`

**Why WebUI Keeps Codebase:**
- Enables incremental analysis (analyze 5 findings, then 5 more later)
- Avoids re-cloning repository between batches
- User can manually delete session when done

---

## WebSocket Communication

### Connection Flow

1. **Client connects**: `new WebSocket('ws://localhost:8765/ws/{session_id}')`
2. **Server accepts**: `await websocket.accept()`
3. **Server registers**: Adds WebSocket to `connections[session_id]` list
4. **Client sends ping**: Every 30 seconds sends `{type: "ping"}`
5. **Server responds**: Sends `{type: "pong"}`
6. **Server broadcasts**: Events to all connections for that session
7. **Client disconnects**: Server removes from connections list

### Event Types

#### 1. `analysis_started`

```json
{
  "type": "analysis_started",
  "data": {
    "finding_hash": "abc123",
    "timestamp": "2025-12-23T14:31:00Z"
  }
}
```

**Frontend Action**: Show spinner icon in table row.

---

#### 2. `analysis_progress`

```json
{
  "type": "analysis_progress",
  "data": {
    "finding_hash": "abc123",
    "iteration": 5,
    "max_iterations": 30,
    "last_action": "Searching for input validation...",
    "timestamp": "2025-12-23T14:31:15Z"
  }
}
```

**Frontend Action**: Update spinner text with last action.

---

#### 3. `tool_execution`

```json
{
  "type": "tool_execution",
  "data": {
    "finding_hash": "abc123",
    "tool_name": "read_file",
    "tool_args": {"file_path": "src/users.js", "line_range": "10-50"},
    "timestamp": "2025-12-23T14:31:18Z"
  }
}
```

**Frontend Action**: Add to conversation log in analysis modal.

---

#### 4. `analysis_complete`

```json
{
  "type": "analysis_complete",
  "data": {
    "finding_hash": "abc123",
    "result": "CONFIRMED",
    "confidence": 0.85,
    "justification": "SQL injection confirmed...",
    "duration_seconds": 45.2,
    "timestamp": "2025-12-23T14:31:45Z"
  }
}
```

**Frontend Action**:
- Remove spinner
- Add color-coded background (red for CONFIRMED)
- Show confidence and justification
- Enable "Write Back" button

---

#### 5. `analysis_failed`

```json
{
  "type": "analysis_failed",
  "data": {
    "finding_hash": "abc123",
    "error": "Agent exceeded max iterations",
    "timestamp": "2025-12-23T14:32:00Z"
  }
}
```

**Frontend Action**:
- Remove spinner
- Show error icon and message
- Enable "Retry" button

---

#### 6. `batch_progress`

```json
{
  "type": "batch_progress",
  "data": {
    "total_findings": 15,
    "completed_count": 8,
    "failed_count": 1,
    "pending_count": 6,
    "timestamp": "2025-12-23T14:32:10Z"
  }
}
```

**Frontend Action**: Update progress bar.

---

### Multi-Tab Support

**Implementation**: `WebSocketManager` stores list of connections per session:

```python
self.connections: Dict[str, List[WebSocket]] = {}
```

**Broadcast**: Sends message to all connections:

```python
for connection in self.connections[session_id]:
    await connection.send_json(message)
```

**Cleanup**: Failed connections automatically removed from list.

---

### Reconnection

**Auto-reconnect**: Client attempts reconnection up to 5 times with exponential backoff:

```javascript
reconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error('Max reconnection attempts reached');
        return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    setTimeout(() => {
        console.log(`Reconnecting (attempt ${this.reconnectAttempts})...`);
        this.connect(this.sessionId);
    }, delay);
}
```

**Backoff Schedule**: 2s, 4s, 8s, 16s, 30s (capped at 30s).

---

## Security

### Input Validation

**Implementation**: `web_ui/middleware/security.py` contains `SecurityValidator` class.

**Validation Rules**:

| Input Type | Validation Method | Pattern/Whitelist |
|------------|-------------------|-------------------|
| Project Name | Regex | `^[a-zA-Z0-9._-]+$`, max 255 chars |
| Branch Name | Regex | `^[a-zA-Z0-9._/-]+$`, max 255 chars |
| Session ID | Format | `^\d{8}_\d{6}_[a-zA-Z0-9]{6}$` |
| Severity | Whitelist | `{CRITICAL, HIGH, MEDIUM, LOW, INFO}` |
| State | Whitelist | `{TO_VERIFY, CONFIRMED, NOT_EXPLOITABLE, PROPOSED_NOT_EXPLOITABLE, URGENT}` |
| Model Name | Whitelist | `{gemini-2.5-pro, gemini-2.5-flash}` |
| Finding Hash | Alphanumeric | Max 128 chars |

**Example**:

```python
@staticmethod
def validate_session_id(session_id: str) -> None:
    pattern = r'^\d{8}_\d{6}_[a-zA-Z0-9]{6}$'
    if not re.match(pattern, session_id):
        raise ValueError(f"Invalid session ID format: {session_id}")
```

---

### Output Sanitization

**HTML Escaping**: All user-generated content (justifications, tool results) escaped before rendering:

```javascript
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
```

**Pydantic Sanitization**: Response models use Pydantic validators.

---

### CORS Configuration

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8765", "http://127.0.0.1:8765"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"]
)
```

**Restriction**: Only localhost origins allowed.

---

### Rate Limiting

**Implementation**: In-memory rate limiter (resets on server restart).

**Limits**:
- `/api/analysis/start`: 5 requests per 60 seconds
- `/api/findings/fetch`: 10 requests per 60 seconds

**Example**:

```python
rate_limiter.check_rate_limit("analysis_start", max_requests=5, window_seconds=60)
```

**Note**: Production should use Redis-backed rate limiter.

---

### Path Traversal Prevention

**Validation**: All session IDs validated against strict format before file operations.

**Safe Path Check**: Reuses `validate_safe_path()` from `agent_tools.py`.

**Example**:

```python
session_path = os.path.join(ANALYSIS_SESSIONS_DIR, session_id, "session.json")
if not session_path.startswith(os.path.abspath(ANALYSIS_SESSIONS_DIR)):
    raise ValueError("Invalid session path")
```

---

### Secrets Management

**Environment Variables**: All sensitive data stored in `.env` file (gitignored).

**Required Variables**:
- `PROJECT_ID`: GCP project ID
- `DEFAULT_LOCATION`: Vertex AI region
- `BASE_URL`: Checkmarx instance URL
- `REFRESH_TOKEN`: Checkmarx API token

**Git Exclusion**: `.env` file in `.gitignore`.

---

## Development Notes

### Local Tool vs. Target Architecture

**Current (Local Tool)**:
- Single-user
- JSON file storage
- No authentication
- Runs on localhost only
- In-memory rate limiting
- Direct file system access

**Future (Production)**:
- Multi-user, multi-tenant
- PostgreSQL/MongoDB database
- OAuth2 authentication
- Cloud-deployed (GCP/AWS)
- Redis-backed rate limiting
- Object storage (GCS/S3)
- Kubernetes deployment
- Audit logging

**Rationale for Local First**:
- Quick proof-of-concept for internal stakeholders
- No infrastructure setup required
- Immediate usability for security team
- Faster iteration during development

---

### Code Reuse from CLI

**Modified Files** (minimal changes):

1. **sast_triage/agent.py**: Added `progress_callback` parameter + 7 event emission points
2. **sast_triage/agent_logging.py**: Added `get_finding_log()` method
3. **utils/checkmarx_helpers.py**: Added `states` parameter for filtering
4. **config.py**: Added Web UI constants

**Reused Files** (no changes):
- `sast_triage/agent_tools.py`: All tools reused
- `utils/checkmarx_client.py`: Checkmarx API wrapper
- `utils/github_helpers.py`: Git repository cloning
- `config.py`: Environment variables

**Code Reuse**: 95%

---

### Why FastAPI?

FastAPI was chosen for its native async/await and WebSocket support, which are essential for real-time progress updates during analysis. It also provides built-in request/response validation via Pydantic and automatic API documentation.

---

### Why No Database?

**Rationale**:
- This is a proof-of-concept for internal use
- Expected usage: 1-5 concurrent users (security team)
- Session data is append-only (no complex queries needed)
- JSON files are human-readable for debugging
- Zero setup overhead

**When to Add Database**:
- More than 10 concurrent users
- Need for complex queries (search, filtering)
- Audit trail requirements
- Cloud deployment

**Recommended**: PostgreSQL (relational) or MongoDB (document store)

---

## Troubleshooting

### WebSocket Connection Fails

**Symptoms**: Console shows `WebSocket connection failed`

**Possible Causes**:
1. Server not running
2. Session ID invalid
3. CORS issue

**Debugging Steps**:
```bash
# Check server is running
curl http://localhost:8765/health

# Check session exists
ls analysis_sessions/{session_id}/session.json

# Check browser console for CORS errors
```

---

### Analysis Stuck at "Starting..."

**Symptoms**: Button shows "Analysis Running..." but no progress

**Possible Causes**:
1. Google Cloud credentials not configured
2. Checkmarx API token expired
3. Network connectivity issue

**Debugging Steps**:
```bash
# Check environment variables
cat .env | grep PROJECT_ID
cat .env | grep REFRESH_TOKEN

# Test Google Cloud auth
gcloud auth application-default login

# Check Checkmarx connectivity
curl -H "Authorization: Bearer $REFRESH_TOKEN" $BASE_URL/api/projects
```

---

### Session Not Saving

**Symptoms**: Session disappears after refresh

**Possible Causes**:
1. File permissions issue
2. `analysis_sessions/` directory doesn't exist

**Debugging Steps**:
```bash
# Check directory exists
ls -la analysis_sessions/

# Create if missing
mkdir -p analysis_sessions

# Check permissions
chmod 755 analysis_sessions
```

---

### Rate Limit Exceeded

**Symptoms**: 429 error response

**Cause**: Too many requests in short time

**Resolution**: Wait 60 seconds and retry

---

### Port Already in Use

**Symptoms**: `Address already in use` error on startup

**Cause**: Another process using port 8765

**Debugging Steps**:
```bash
# Find process
lsof -i :8765

# Kill process
kill -9 <PID>

# Or use different port
# Edit config.py → WEB_UI_PORT = 8766
```

---

## Performance Considerations

### Concurrent Analysis Limit

**Current**: 1 concurrent analysis at a time

**Rationale**:
- Analysis is LLM-intensive (30-60s per finding)
- Vertex AI has rate limits
- Local machine may not handle multiple parallel repository clones

**Future Consideration**: Increase to 3-5 with resource monitoring.

---

### Session Storage Limits

**Current**: 100 sessions max (oldest auto-deleted)

**Rationale**: JSON file listing becomes slow with 1000+ files

**Future Consideration**: Move to database for unlimited sessions.

---

### WebSocket Message Size

**Current**: No limit (entire conversation log sent)

**Potential Issue**: Large conversation logs (10+ MB) may cause WebSocket message size issues

**Future Consideration**: Paginate conversation logs, send incremental updates only.

---

## API Reference

See OpenAPI documentation at `http://localhost:8765/docs` when server is running.