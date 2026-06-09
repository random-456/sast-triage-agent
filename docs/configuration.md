# Configuration

## Environment Variables

The application reads configuration from a `.env` file in the project root. Copy `.env.example` to `.env` and set the values.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BASE_URL` | Checkmarx One instance URL | `https://cx.example.com` |
| `REFRESH_TOKEN` | Checkmarx API refresh token | `eyJ...` |

### Vertex AI

The agent uses Google Gemini on Vertex AI. Auth is via Application Default Credentials (`gcloud auth application-default login`).

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | GCP project ID (required). |
| `GOOGLE_CLOUD_LOCATION` | Vertex AI region. Defaults to `europe-west4`. |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKENS` | (none) | Per-host GitHub access tokens for HTTPS clones. Format: `host=token,host=token` (e.g. `github.com=ghp_xxx,ghe.example.com=ghp_yyy`). Hostname is matched case-insensitively against the Checkmarx-supplied repo URL; unmatched hosts fall back to the local git CLI credentials. The token is sent as an HTTP Basic Authorization header (username `x-access-token`) for the clone only and is never written to the cloned repo's git config. |

### `.env.example`

```env
# Checkmarx One Configuration
BASE_URL=https://
REFRESH_TOKEN=refresh-token

# Vertex AI Configuration. Auth via `gcloud auth application-default login`.
GOOGLE_CLOUD_PROJECT=gcp-project-id
GOOGLE_CLOUD_LOCATION=europe-west4

# Optional: per-host GitHub access tokens used when cloning HTTPS repos.
# Format: comma-separated "host=token" pairs. Hostname is matched
# case-insensitively against the URL returned by Checkmarx; non-matching
# hosts fall back to the local git CLI credentials. The token is sent as an
# HTTP Basic Authorization header (username "x-access-token") for the clone
# only and is never written to .git/config or the URL.
# GITHUB_TOKENS=github.com=ghp_xxx,ghe.example.com=ghp_yyy
```

## Application Constants

Defined in `config.py`. These rarely need modification but can be adjusted for specific environments.

### Path Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `TEMP_DIR` | `temp` | Temporary directory for cloned repos and findings |
| `ASSETS_DIR` | `assets` | Directory for static assets (certificates) |
| `DEFAULT_OUTPUT_DIR` | `output` | Default output directory for results |
| `CODEBASE_DIR` | `temp/codebase` | Where the repository is cloned |
| `FINDINGS_DIR` | `temp/findings` | Where fetched findings are stored |
| `CERTIFICATES_CRT_FILE` | `assets/abcorg-ca.crt` | CA certificate for corporate SSL |

### Model Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TRIAGE_MODEL` | `gemini-2.5-pro` | Default LLM model for triage analysis |
| `DEFAULT_JUSTIFICATION_COMPARISON_MODEL` | `gemini-2.5-flash` | Model used for benchmark justification comparison |

### Analysis Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_SEARCH_RESULTS` | `50` | Safety cap for code search results returned to the LLM |

### Per-Finding Graph Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_RESEARCH_ITERATIONS` | `5` | Research-node visits before a forced aggregate |
| `MAX_REANALYSIS_LOOPS` | `2` | Critic to analyst reanalysis loops before aggregate |
| `MAX_TOOL_CALLS_PER_RESEARCH` | `10` | Tool-call turns within one research-node visit |
| `MAX_RESEARCH_STALL` | `2` | Consecutive research visits that add no new evidence before the loop stops with `no_progress` |
| `INITIAL_SAMPLES` | `2` | Self-consistency samples collected before a tiebreaker |
| `DEFAULT_SAMPLES` | `3` | Maximum self-consistency samples per finding |
| `ANALYST_TEMPERATURES` | `[0.1, 0.3, 0.5]` | Per-sample analyst temperatures for diversity |
| `CRITIC_TEMPERATURE` | `0.6` | Critic temperature, higher than the analyst to defeat sycophancy |
| `CONFIDENCE_AGREEMENT_WEIGHT` | `0.7` | Weight of agreement vs evidence strength in final confidence |
| `GRAPH_RECURSION_LIMIT` | `50` | Safety net on per-finding graph node executions |

### Disposition Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `CONFIDENCE_THRESHOLD` | `0.85` | A non-exploitable verdict below this confidence is routed to `PROPOSED_NOT_EXPLOITABLE` for human review instead of `NOT_EXPLOITABLE`. Conservative placeholder; calibrate against the gold-set. |
| `NON_CONVERGENT_CONFIDENCE_CAP` | `0.8` | A not-exploitable verdict that stopped without genuine critic approval (a circuit breaker fired) is capped to this, below `CONFIDENCE_THRESHOLD`, so it routes to `PROPOSED_NOT_EXPLOITABLE` for human review. Conservative placeholder; calibrate against the gold-set. |

### Checkmarx Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `CHECKMARX_CLIENT_ID` | `ast-app` | OAuth client ID for Checkmarx One |
| `CHECKMARX_REALM` | `abcorg` | Checkmarx tenant/realm name |
| `CHECKMARX_API_LIMIT` | `1000` | Max findings per API request (pagination) |
| `DEFAULT_SEVERITIES` | `["HIGH", "MEDIUM"]` | Default severity filter |
| `DEFAULT_BRANCH` | `default.SecurityPipeline` | Default branch for scan lookup |
| `DEFAULT_STATES` | `["TO_VERIFY"]` | Default state filter |
| `CHECKMARX_STATES` | All five states | Valid Checkmarx states for interactive selection |

## SSL Configuration

The application sets `REQUESTS_CA_BUNDLE` and `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` environment variables at startup to point to the corporate CA certificate file. If the certificate file does not exist at the configured path, standard SSL verification is used instead.

## Supported Models

The agent targets Google Gemini models on Vertex AI through the `ChatVertexAI` client.

Examples:
```bash
--model gemini-2.5-pro         # default
--model gemini-2.5-flash       # faster, lower cost
```

## Dependencies

Core dependencies are listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `langchain`, `langchain-core` | Tool definitions and message primitives |
| `langgraph` | Per-finding subgraph state machine (research, analyst, critic and aggregate) |
| `langchain-google-vertexai` | Gemini-on-Vertex client (gRPC transport) |
| `pydantic` | Data validation and models |
| `click` | CLI framework |
| `questionary` | Interactive prompt library |
| `requests` | HTTP client for Checkmarx API |
| `python-dotenv` | `.env` file loading |
| `pytest`, `pytest-asyncio` | Testing |

## Prerequisites

- Python 3.10+
- A Google Cloud project with the Vertex AI API enabled, plus Application Default Credentials (`gcloud auth application-default login`)
- Access to a Checkmarx One instance with a valid refresh token
- Git installed (for repository cloning)
