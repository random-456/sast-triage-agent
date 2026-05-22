# Configuration

## Environment Variables

The application reads configuration from a `.env` file in the project root. Copy `.env.example` to `.env` and set the values.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BASE_URL` | Checkmarx One instance URL | `https://cx.example.com` |
| `REFRESH_TOKEN` | Checkmarx API refresh token | `eyJ...` |

### Google GenAI Backend

The agent uses a single Gemini client that talks to one of two backends. Configure exactly one mode.

| Variable | Mode | Description |
|----------|------|-------------|
| `GOOGLE_GENAI_USE_VERTEXAI` | Vertex AI | Set to `true` to use Vertex AI (production). |
| `GOOGLE_CLOUD_PROJECT` | Vertex AI | GCP project ID. Required when Vertex AI is enabled. |
| `GOOGLE_CLOUD_LOCATION` | Vertex AI | Region. Defaults to `europe-west4`. |
| `GOOGLE_API_KEY` | AI Studio | Google AI Studio API key (local development). |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKENS` | -- | Per-host GitHub access tokens for HTTPS clones. Format: `host=token,host=token` (e.g. `github.com=ghp_xxx,ghe.example.com=ghp_yyy`). Hostname is matched case-insensitively against the Checkmarx-supplied repo URL; unmatched hosts fall back to the local git CLI credentials. The token is sent as an HTTP Basic Authorization header (username `x-access-token`) for the clone only — never written to the cloned repo's git config. |

### `.env.example`

```env
# Checkmarx One Configuration
BASE_URL=https://
REFRESH_TOKEN=refresh-token

# Google GenAI backend: choose ONE mode.
# Production (Vertex AI), auth via `gcloud auth application-default login`:
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=gcp-project-id
GOOGLE_CLOUD_LOCATION=europe-west4
# Local development (Google AI Studio), prepaid and budget-cappable:
# GOOGLE_API_KEY=AIza...

# Optional: per-host GitHub access tokens used when cloning HTTPS repos.
# Format: comma-separated "host=token" pairs. Hostname is matched
# case-insensitively against the URL returned by Checkmarx; non-matching
# hosts fall back to the local git CLI credentials. The token is sent as an
# HTTP Basic Authorization header (username "x-access-token") for the clone
# only — never written to .git/config or the URL.
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
| `CERTIFICATES_CRT_FILE` | `assets/airbus-ca.crt` | CA certificate for corporate SSL |

### Model Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TRIAGE_MODEL` | `gemini-2.5-pro` | Default LLM model for triage analysis |
| `DEFAULT_JUSTIFICATION_COMPARISON_MODEL` | `gemini-2.5-flash` | Model used for benchmark justification comparison |

### Analysis Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_ANALYSIS_ITERATIONS` | `30` | Maximum LLM iterations per finding before timeout |
| `MAX_SEARCH_RESULTS` | `50` | Safety cap for code search results returned to the LLM |
| `MAX_LOG_RESULT_LENGTH` | `5000` | Maximum character length for tool results in session logs |

### Checkmarx Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `CHECKMARX_CLIENT_ID` | `ast-app` | OAuth client ID for Checkmarx One |
| `CHECKMARX_REALM` | `airbus` | Checkmarx tenant/realm name |
| `CHECKMARX_API_LIMIT` | `1000` | Max findings per API request (pagination) |
| `DEFAULT_SEVERITIES` | `["HIGH", "MEDIUM"]` | Default severity filter |
| `DEFAULT_BRANCH` | `default.SecurityPipeline` | Default branch for scan lookup |
| `DEFAULT_STATES` | `["TO_VERIFY"]` | Default state filter |
| `CHECKMARX_STATES` | All five states | Valid Checkmarx states for interactive selection |

## SSL Configuration

The application sets `REQUESTS_CA_BUNDLE` and `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` environment variables at startup to point to the corporate CA certificate file. If the certificate file does not exist at the configured path, standard SSL verification is used instead.

## Supported Models

The agent targets Google Gemini models through the unified `ChatGoogleGenerativeAI` client, on either the Vertex AI or AI Studio backend.

Examples:
```bash
--model gemini-2.5-pro         # default
--model gemini-2.5-flash       # faster, lower cost
```

## Dependencies

Core dependencies are listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `langchain`, `langchain-core` | Agent framework and tool definitions |
| `langchain-google-genai`, `google-genai` | Gemini integration (Vertex AI and AI Studio) |
| `pydantic` | Data validation and models |
| `click` | CLI framework |
| `questionary` | Interactive prompt library |
| `requests` | HTTP client for Checkmarx API |
| `python-dotenv` | `.env` file loading |
| `pytest`, `pytest-asyncio` | Testing |

## Prerequisites

- Python 3.10+
- A Google GenAI backend, either:
  - Vertex AI: a Google Cloud project with the Vertex AI API enabled, plus Application Default Credentials (`gcloud auth application-default login`), or
  - Google AI Studio: a `GOOGLE_API_KEY` (prepaid, budget-cappable)
- Access to a Checkmarx One instance with a valid refresh token
- Git installed (for repository cloning)
