# Configuration

## Environment Variables

The application reads configuration from a `.env` file in the project root. Copy `.env.example` to `.env` and set the values.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BASE_URL` | Checkmarx One instance URL | `https://cx.example.com` |
| `REFRESH_TOKEN` | Checkmarx API refresh token | `eyJ...` |
| `PROJECT_ID` | Google Cloud project ID for Vertex AI | `my-gcp-project` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_LOCATION` | `europe-west4` | Vertex AI region |
| `SAST_TRIAGE_TRACE` | -- | Set to `true`, `1`, or `yes` to enable Phoenix tracing |

### `.env.example`

```env
# Checkmarx One Configuration
BASE_URL=https://
REFRESH_TOKEN=refresh-token

# Vertex AI Configuration
PROJECT_ID=gcp-project-id
DEFAULT_LOCATION=europe-west4
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
| `MAX_ANALYSIS_ITERATIONS` | `30` | Maximum LLM iterations per finding before timeout |
| `MAX_SEARCH_RESULTS` | `50` | Safety cap for code search results returned to the LLM |
| `MAX_LOG_RESULT_LENGTH` | `5000` | Maximum character length for tool results in session logs |

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

Any model accessible through Google Vertex AI can be used. The agent automatically selects the appropriate LangChain backend:

- **Gemini models** (default): Uses `ChatVertexAI` -- any model name not containing "claude"
- **Claude models**: Uses `ChatAnthropicVertex` -- model names containing "claude"

Examples:
```bash
--model gemini-2.5-pro        # Gemini (default)
--model gemini-2.5-flash       # Gemini Flash
--model claude-sonnet-4-5      # Claude via Vertex AI
```

## Dependencies

Core dependencies are listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `langchain`, `langchain-core` | Agent framework and tool definitions |
| `langchain-google-vertexai` | Vertex AI LLM integration |
| `anthropic` | Claude model support |
| `pydantic` | Data validation and models |
| `click` | CLI framework |
| `questionary` | Interactive prompt library |
| `requests` | HTTP client for Checkmarx API |
| `python-dotenv` | `.env` file loading |
| `pytest`, `pytest-asyncio` | Testing |

### Optional Dependencies

For LLM tracing with Phoenix:
```bash
pip install arize-phoenix openinference-instrumentation-langchain
```

## Prerequisites

- Python 3.12+
- Access to a Google Cloud project with Vertex AI API enabled
- Application Default Credentials configured: `gcloud auth application-default login`
- Access to a Checkmarx One instance with a valid refresh token
- Git installed (for repository cloning)
