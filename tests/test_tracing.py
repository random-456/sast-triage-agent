"""Tests for optional Phoenix tracing integration."""

from unittest.mock import patch, MagicMock

import pytest

from sast_triage.tracing import (
    initialize_tracing,
    is_tracing_enabled,
    shutdown_tracing,
    wait_for_trace_review,
)


class TestIsTracingEnabled:
    def test_disabled_by_default(self) -> None:
        """Tracing is disabled when env var is not set."""
        with patch.dict("os.environ", {}, clear=True):
            assert is_tracing_enabled() is False

    @pytest.mark.parametrize("value", ["true", "1", "yes", "True", "YES"])
    def test_enabled_via_env(self, value: str) -> None:
        """Tracing is enabled for truthy SAST_TRIAGE_TRACE values."""
        with patch.dict("os.environ", {"SAST_TRIAGE_TRACE": value}):
            assert is_tracing_enabled() is True

    @pytest.mark.parametrize("value", ["false", "0", "no", ""])
    def test_disabled_for_falsy_values(self, value: str) -> None:
        """Tracing stays disabled for non-truthy values."""
        with patch.dict("os.environ", {"SAST_TRIAGE_TRACE": value}):
            assert is_tracing_enabled() is False


class TestInitializeTracing:
    def test_logs_warning_when_phoenix_not_installed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """initialize_tracing logs a warning when Phoenix is missing."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False

        with (
            patch.dict("sys.modules", {"phoenix": None}),
            caplog.at_level("WARNING"),
        ):
            initialize_tracing()

        assert "packages not installed" in caplog.text

    def test_no_crash_when_phoenix_not_installed(self) -> None:
        """initialize_tracing does not raise when Phoenix is missing."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False

        with patch.dict("sys.modules", {"phoenix": None}):
            initialize_tracing()

    def test_skips_when_already_initialized(self) -> None:
        """initialize_tracing is a no-op after first successful init."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = True

        try:
            # Should return immediately without importing phoenix
            with patch(
                "builtins.__import__", side_effect=AssertionError
            ):
                initialize_tracing()
        finally:
            tracing_module._phoenix_initialized = False

    def test_handles_runtime_error_gracefully(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """initialize_tracing catches non-ImportError exceptions."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False

        mock_px = MagicMock()
        mock_px.launch_app.side_effect = RuntimeError("port in use")
        mock_instrumentor = MagicMock()

        mock_otel = MagicMock()

        with (
            patch.dict(
                "sys.modules",
                {
                    "phoenix": mock_px,
                    "phoenix.otel": mock_otel,
                    "openinference": MagicMock(),
                    "openinference.instrumentation": MagicMock(),
                    "openinference.instrumentation.langchain": mock_instrumentor,
                },
            ),
            caplog.at_level("WARNING"),
        ):
            initialize_tracing()

        assert "Failed to initialize Phoenix tracing" in caplog.text
        assert tracing_module._phoenix_initialized is False


    def test_successful_initialization_calls_register(self) -> None:
        """initialize_tracing calls register() and passes provider to instrument()."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False

        mock_px = MagicMock()
        mock_provider = MagicMock()
        mock_otel = MagicMock()
        mock_otel.register.return_value = mock_provider
        mock_instrumentor_cls = MagicMock()
        mock_instrumentor_mod = MagicMock()
        mock_instrumentor_mod.LangChainInstrumentor = mock_instrumentor_cls

        try:
            with patch.dict(
                "sys.modules",
                {
                    "phoenix": mock_px,
                    "phoenix.otel": mock_otel,
                    "openinference": MagicMock(),
                    "openinference.instrumentation": MagicMock(),
                    "openinference.instrumentation.langchain": mock_instrumentor_mod,
                },
            ):
                initialize_tracing()

            mock_otel.register.assert_called_once_with(
                project_name="sast-triage",
            )
            mock_instrumentor_cls().instrument.assert_called_once_with(
                tracer_provider=mock_provider,
            )
            assert tracing_module._phoenix_initialized is True
            assert tracing_module._tracer_provider is mock_provider
        finally:
            tracing_module._phoenix_initialized = False
            tracing_module._tracer_provider = None
            tracing_module._phoenix_session = None


class TestShutdownTracing:
    def test_noop_when_not_initialized(self) -> None:
        """shutdown_tracing is safe to call when nothing was started."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False
        tracing_module._phoenix_session = None
        shutdown_tracing()
        assert tracing_module._phoenix_initialized is False

    def test_calls_close_app(self) -> None:
        """shutdown_tracing flushes tracer, calls close_app, resets state."""
        import sast_triage.tracing as tracing_module

        mock_provider = MagicMock()
        tracing_module._phoenix_initialized = True
        tracing_module._phoenix_session = MagicMock()
        tracing_module._tracer_provider = mock_provider

        call_order = []
        mock_provider.shutdown.side_effect = (
            lambda: call_order.append("provider_shutdown")
        )
        mock_px = MagicMock()
        mock_px.close_app.side_effect = (
            lambda: call_order.append("close_app")
        )

        with patch.dict("sys.modules", {"phoenix": mock_px}):
            shutdown_tracing()

        mock_provider.shutdown.assert_called_once()
        mock_px.close_app.assert_called_once()
        assert call_order == ["provider_shutdown", "close_app"]
        assert tracing_module._phoenix_initialized is False
        assert tracing_module._phoenix_session is None
        assert tracing_module._tracer_provider is None

    def test_resets_state_even_on_error(self) -> None:
        """shutdown_tracing resets state even if close_app raises."""
        import sast_triage.tracing as tracing_module

        mock_provider = MagicMock()
        tracing_module._phoenix_initialized = True
        tracing_module._phoenix_session = MagicMock()
        tracing_module._tracer_provider = mock_provider

        mock_px = MagicMock()
        mock_px.close_app.side_effect = RuntimeError("boom")
        with patch.dict("sys.modules", {"phoenix": mock_px}):
            shutdown_tracing()

        assert tracing_module._phoenix_initialized is False
        assert tracing_module._phoenix_session is None
        assert tracing_module._tracer_provider is None


class TestWaitForTraceReview:
    def test_noop_when_not_initialized(self) -> None:
        """wait_for_trace_review returns immediately if tracing is off."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = False
        # Should not block or raise
        wait_for_trace_review()

    def test_blocks_then_shuts_down(self) -> None:
        """wait_for_trace_review waits for input then calls shutdown."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = True
        tracing_module._phoenix_session = MagicMock()

        mock_px = MagicMock()
        with (
            patch("builtins.input", return_value=""),
            patch.dict("sys.modules", {"phoenix": mock_px}),
        ):
            wait_for_trace_review()

        mock_px.close_app.assert_called_once()
        assert tracing_module._phoenix_initialized is False

    def test_handles_keyboard_interrupt(self) -> None:
        """wait_for_trace_review handles Ctrl+C gracefully."""
        import sast_triage.tracing as tracing_module

        tracing_module._phoenix_initialized = True
        tracing_module._phoenix_session = MagicMock()

        mock_px = MagicMock()
        with (
            patch(
                "builtins.input", side_effect=KeyboardInterrupt
            ),
            patch.dict("sys.modules", {"phoenix": mock_px}),
        ):
            wait_for_trace_review()

        assert tracing_module._phoenix_initialized is False


class TestCliTraceFlag:
    """Verify --trace flag is wired into both CLI commands."""

    @pytest.fixture()
    def runner(self):
        """Provide a Click CLI test runner."""
        from click.testing import CliRunner

        return CliRunner()

    def test_run_help_shows_trace_option(self, runner) -> None:
        """run --help lists the --trace option."""
        from run_triage import cli

        result = runner.invoke(cli, ["run", "--help"])
        assert "--trace" in result.output

    def test_interactive_help_shows_trace_option(self, runner) -> None:
        """interactive --help lists the --trace option."""
        from run_triage import cli

        result = runner.invoke(cli, ["interactive", "--help"])
        assert "--trace" in result.output
