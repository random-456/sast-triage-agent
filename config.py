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

CERTIFICATES_CRT_FILE = os.path.join(ASSETS_DIR, "airbus-ca.crt")
FINDINGS_CSV_FILE = os.path.join(FINDINGS_DIR, "triage_list.csv")
FINDINGS_JSON_FILE = os.path.join(FINDINGS_DIR, "findings_details.json")

# Vertex AI Configuration
DEFAULT_TRIAGE_MODEL = "gemini-2.5-pro"  # Global default and --model fallback
DEFAULT_JUSTIFICATION_COMPARISON_MODEL = "gemini-2.5-flash"
DEFAULT_GCP_LOCATION = "europe-west4"  # Default Vertex AI region

# Per-node model defaults. Point any node at a Claude model (name containing
# "claude") to run it on Anthropic via Vertex; the rest stay on Gemini. A
# matching --research-model/--analyst-model/--critic-model flag overrides per
# run, and --model overrides all three at once.
DEFAULT_RESEARCH_MODEL = DEFAULT_TRIAGE_MODEL
DEFAULT_ANALYST_MODEL = DEFAULT_TRIAGE_MODEL
DEFAULT_CRITIC_MODEL = DEFAULT_TRIAGE_MODEL

# Per-node Vertex region overrides. None means use the resolved global location
# (GOOGLE_CLOUD_LOCATION, default DEFAULT_GCP_LOCATION). Set a node's region to
# one that serves its provider when mixing Gemini and Claude across nodes, since
# Claude on Vertex is served only from specific regions.
DEFAULT_RESEARCH_LOCATION: str | None = None
DEFAULT_ANALYST_LOCATION: str | None = None
DEFAULT_CRITIC_LOCATION: str | None = None

# Analysis Configuration
MAX_SEARCH_RESULTS = 50  # Safety cap for search results

# Per-finding graph circuit breakers (Phase 2 LangGraph subgraph)
MAX_RESEARCH_ITERATIONS = 5  # Research-node visits before a forced aggregate
MAX_REANALYSIS_LOOPS = 2  # Critic -> analyst reanalysis loops before aggregate
MAX_TOOL_CALLS_PER_RESEARCH = 10  # Tool-call turns within one research-node visit
# Consecutive research visits that add no new evidence before the per-finding
# loop is declared stalled and terminated with stop_reason="no_progress",
# instead of burning the full MAX_RESEARCH_ITERATIONS budget on evidence that
# cannot be obtained. Conservative placeholder; calibrate against the gold-set.
MAX_RESEARCH_STALL = 2
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
# A not-exploitable verdict produced when the per-finding loop stops without
# genuine critic approval (a circuit breaker fired) has not earned a confident
# dismissal: it is often a single unvalidated sample whose agreement_rate is
# trivially 1.0. Cap its confidence to this value so it routes to
# PROPOSED_NOT_EXPLOITABLE for human review instead of NOT_EXPLOITABLE. Must
# stay below CONFIDENCE_THRESHOLD. Conservative placeholder; calibrate against
# the gold-set.
NON_CONVERGENT_CONFIDENCE_CAP = 0.8

# Checkmarx API Configuration
CHECKMARX_CLIENT_ID = "ast-app"  # Default client ID for Checkmarx One
CHECKMARX_REALM = "airbus"  # Checkmarx realm/tenant name
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


def resolve_vertex_config() -> tuple[str, str]:
    """Resolve the Vertex AI project and location from the environment.

    Returns:
        (project, location). location defaults to DEFAULT_GCP_LOCATION when
        GOOGLE_CLOUD_LOCATION is not set.

    Raises:
        RuntimeError: if GOOGLE_CLOUD_PROJECT is missing.
    """
    project = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise RuntimeError(
            "GOOGLE_CLOUD_PROJECT is not set. Vertex AI requires a GCP "
            "project; set GOOGLE_CLOUD_PROJECT in your .env."
        )
    location = os.getenv("GOOGLE_CLOUD_LOCATION", DEFAULT_GCP_LOCATION)
    return project, location