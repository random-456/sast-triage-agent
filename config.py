"""
Configuration constants for SAST Triage Agent
"""
import os

APP_NAME = "SAST Triage Agent"

# Path Configuration
TEMP_DIR = "temp"
ASSETS_DIR = "assets"
DEFAULT_OUTPUT_DIR = "output"

CODEBASE_DIR = os.path.join(TEMP_DIR, "codebase")
FINDINGS_DIR = os.path.join(TEMP_DIR, "findings")

CERTIFICATES_CRT_FILE = os.path.join(ASSETS_DIR, "abcorg-ca.crt")
FINDINGS_CSV_FILE = os.path.join(FINDINGS_DIR, "triage_list.csv")
FINDINGS_JSON_FILE = os.path.join(FINDINGS_DIR, "findings_details.json")

# Google GenAI Configuration
DEFAULT_TRIAGE_MODEL = "gemini-2.5-pro"
DEFAULT_JUSTIFICATION_COMPARISON_MODEL = "gemini-2.5-flash"
DEFAULT_GCP_LOCATION = "europe-west4"  # Vertex AI region when GOOGLE_GENAI_USE_VERTEXAI=true

# Analysis Configuration
MAX_SEARCH_RESULTS = 50  # Safety cap for search results
MAX_LOG_RESULT_LENGTH = 5000  # Maximum length for logging tool results

# Per-finding graph circuit breakers (Phase 2 LangGraph subgraph)
MAX_RESEARCH_ITERATIONS = 5  # Research-node visits before a forced aggregate
MAX_REANALYSIS_LOOPS = 2  # Critic -> analyst reanalysis loops before aggregate
MAX_TOOL_CALLS_PER_RESEARCH = 10  # Tool-call turns within one research-node visit
INITIAL_SAMPLES = 2  # Adaptive sampling starts here; a tiebreaker may add more
DEFAULT_SAMPLES = 3  # Max self-consistency samples per finding (tiebreak ceiling)
# Final confidence = agreement_rate * W + evidence_strength * (1 - W). Weights
# from doc 05; calibrate against the gold-set.
CONFIDENCE_AGREEMENT_WEIGHT = 0.7
# Upper bound on per-finding graph node executions. The circuit breakers above
# terminate the loops well before this; it is a safety net for ainvoke.
GRAPH_RECURSION_LIMIT = 50
# Analyst sampling temperatures, applied per sample slot for diversity; the
# last value is reused if more samples than entries are taken (doc 05).
ANALYST_TEMPERATURES = [0.1, 0.3, 0.5]
CRITIC_TEMPERATURE = 0.6  # Higher than the analyst to defeat sycophancy

# Disposition Configuration
# A non-exploitable verdict below this confidence is routed to
# PROPOSED_NOT_EXPLOITABLE for human attention rather than NOT_EXPLOITABLE.
# Conservative placeholder; calibrate against the gold-set.
CONFIDENCE_THRESHOLD = 0.85

# Checkmarx API Configuration
CHECKMARX_CLIENT_ID = "ast-app"  # Default client ID for Checkmarx One
CHECKMARX_REALM = "abcorg"  # Checkmarx realm/tenant name
CHECKMARX_API_LIMIT = 1000  # Max findings per API request
DEFAULT_SEVERITIES = ["HIGH", "MEDIUM"]  # Default severities to fetch
DEFAULT_BRANCH = "default.SecurityPipeline"  # Default branch for scans
CHECKMARX_STATES = [
    "TO_VERIFY",
    "NOT_EXPLOITABLE",
    "PROPOSED_NOT_EXPLOITABLE",
    "CONFIRMED",
    "URGENT",
]
DEFAULT_STATES = ["TO_VERIFY"]

# Benchmark Configuration
BENCHMARK_DATASETS_DIR = os.path.join("benchmark", "datasets")
BENCHMARK_SECRET_REPORTS_DIR = os.path.join("benchmark", "secret-reports")


def resolve_genai_backend() -> tuple[bool, str | None, str | None]:
    """Resolve the Google GenAI backend from the environment.

    The unified ChatGoogleGenerativeAI client supports two backends: Vertex AI
    (production) and Google AI Studio (local development). Selection is driven
    by environment variables read at process startup.

    Returns:
        (use_vertexai, project, location). project and location are None in
        AI Studio mode.

    Raises:
        RuntimeError: if neither backend is configured.
    """
    if os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").lower() in ("true", "1", "yes"):
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        if not project:
            raise RuntimeError(
                "GOOGLE_GENAI_USE_VERTEXAI is set but GOOGLE_CLOUD_PROJECT is "
                "missing. Set GOOGLE_CLOUD_PROJECT to your Vertex AI project."
            )
        location = os.getenv("GOOGLE_CLOUD_LOCATION", DEFAULT_GCP_LOCATION)
        return True, project, location

    if not os.getenv("GOOGLE_API_KEY"):
        raise RuntimeError(
            "No Google GenAI backend configured. Set GOOGLE_API_KEY for AI "
            "Studio, or GOOGLE_GENAI_USE_VERTEXAI=true with GOOGLE_CLOUD_PROJECT "
            "for Vertex AI."
        )
    return False, None, None