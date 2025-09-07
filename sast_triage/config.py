"""
Configuration constants for SAST Triage Agent
"""

# Path Configuration
CODEBASE_PATH = "codebase"
FINDINGS_PATH = "findings"
DEFAULT_CSV_FILE = f"{FINDINGS_PATH}/triage_list.csv"
DEFAULT_JSON_FILE = f"{FINDINGS_PATH}/findings_details.json"

# Analysis Configuration
MAX_ANALYSIS_ITERATIONS = 15  # Maximum iterations for LLM analysis per finding
MAX_SEARCH_RESULTS = 5000    # Safety cap for search results (~500k tokens)
MAX_LOG_RESULT_LENGTH = 5000  # Maximum length for logging tool results