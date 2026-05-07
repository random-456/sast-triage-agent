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

# Vertex Configuration
DEFAULT_TRIAGE_MODEL = "gemini-2.5-pro"
DEFAULT_JUSTIFICATION_COMPARISON_MODEL = "gemini-2.5-flash"

# Analysis Configuration
MAX_ANALYSIS_ITERATIONS = 30  # Maximum iterations for LLM analysis per finding
MAX_SEARCH_RESULTS = 50  # Safety cap for search results
MAX_LOG_RESULT_LENGTH = 5000  # Maximum length for logging tool results

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