"""Tests for optional Phoenix tracing integration."""

from unittest.mock import patch, MagicMock

import pytest

from sast_triage.tracing import is_tracing_enabled, initialize_tracing


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

        with (
            patch.dict(
                "sys.modules",
                {
                    "phoenix": mock_px,
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
