"""Optional Phoenix tracing integration for LLM observability."""

import logging
import os

logger = logging.getLogger(__name__)

_phoenix_initialized = False


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled via environment variable."""
    return os.getenv("SAST_TRIAGE_TRACE", "").lower() in (
        "true",
        "1",
        "yes",
    )


def initialize_tracing() -> None:
    """
    Initialize Phoenix tracing if available and enabled.

    Starts a local Phoenix server and instruments LangChain.
    Safe to call even if Phoenix is not installed — will log a
    warning and continue.
    """
    global _phoenix_initialized
    if _phoenix_initialized:
        return

    try:
        import phoenix as px
        from openinference.instrumentation.langchain import (
            LangChainInstrumentor,
        )

        px.launch_app()
        logger.info(
            "Phoenix tracing server started at http://localhost:6006"
        )

        LangChainInstrumentor().instrument()
        logger.info("LangChain instrumentation enabled")

        _phoenix_initialized = True

    except ImportError:
        logger.warning(
            "Phoenix tracing requested but packages not installed. "
            "Install with: pip install arize-phoenix "
            "openinference-instrumentation-langchain"
        )
    except Exception as e:
        logger.warning(f"Failed to initialize Phoenix tracing: {e}")
