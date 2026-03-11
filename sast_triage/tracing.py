"""Optional Phoenix tracing integration for LLM observability."""

import logging
import os

logger = logging.getLogger(__name__)

_phoenix_initialized = False
_phoenix_session = None
_tracer_provider = None


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
    global _phoenix_initialized, _phoenix_session, _tracer_provider
    if _phoenix_initialized:
        return

    try:
        import phoenix as px
        from phoenix.otel import register
        from openinference.instrumentation.langchain import (
            LangChainInstrumentor,
        )

        _phoenix_session = px.launch_app()
        logger.info(
            "Phoenix tracing server started at http://localhost:6006"
        )

        _tracer_provider = register(project_name="sast-triage")
        logger.info("OpenTelemetry tracer provider registered")

        LangChainInstrumentor().instrument(
            tracer_provider=_tracer_provider,
        )
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


def shutdown_tracing() -> None:
    """Shut down Phoenix cleanly to release the database file."""
    global _phoenix_initialized, _phoenix_session, _tracer_provider
    if not _phoenix_initialized:
        return

    try:
        if _tracer_provider is not None:
            _tracer_provider.shutdown()
            logger.info("Tracer provider flushed and shut down")

        import phoenix as px

        px.close_app()
        logger.info("Phoenix tracing server stopped")
    except Exception as e:
        logger.debug(f"Phoenix shutdown: {e}")
    finally:
        _tracer_provider = None
        _phoenix_session = None
        _phoenix_initialized = False


def wait_for_trace_review() -> None:
    """
    Block until the user is done reviewing traces, then shut down.

    Only blocks when Phoenix was actually initialized. Prints a
    message directing the user to the Phoenix UI.
    """
    if not _phoenix_initialized:
        return

    print(
        "\nPhoenix tracing UI is available at http://localhost:6006"
        "\nPress Enter to stop Phoenix and exit..."
    )
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

    shutdown_tracing()
